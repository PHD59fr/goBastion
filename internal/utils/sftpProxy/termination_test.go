package sftpProxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/sshHostKey"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

func TestSFTPTerminationDrainsOutput(t *testing.T) {
	for _, halfClose := range []bool{false, true} {
		t.Run(fmt.Sprintf("client_half_close_%t", halfClose), func(t *testing.T) { testSFTPTermination(t, halfClose) })
	}
}

func testSFTPTermination(t *testing.T, halfClose bool) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Paths.HomeBaseDir = t.TempDir()
	config.SetForTesting(cfg)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ssh.MarshalPrivateKey(key, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := int64(listener.Addr().(*net.TCPAddr).Port)
	closeRemote := make(chan struct{})
	releaseRemote := sync.OnceFunc(func() { close(closeRemote) })
	defer releaseRemote()
	backendDone := make(chan error, 1)
	stdout, stderr := strings.Repeat("last response\n", 20000), strings.Repeat("last diagnostic\n", 2000)
	go func() {
		backendDone <- func() error {
			raw, e := listener.Accept()
			if e != nil {
				return e
			}
			defer func() { _ = raw.Close() }()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			sc := &ssh.ServerConfig{NoClientAuth: true}
			sc.AddHostKey(signer)
			server, chans, reqs, e := ssh.NewServerConn(raw, sc)
			if e != nil {
				return e
			}
			defer func() { _ = server.Close() }()
			go ssh.DiscardRequests(reqs)
			incoming, ok := <-chans
			if !ok {
				return fmt.Errorf("missing target channel")
			}
			ch, requests, e := incoming.Accept()
			if e != nil {
				return e
			}
			req, ok := <-requests
			if !ok || req.Type != "subsystem" {
				return fmt.Errorf("missing subsystem request")
			}
			if e := req.Reply(true, nil); e != nil {
				return e
			}
			if halfClose {
				if _, e := io.Copy(io.Discard, ch); e != nil {
					return e
				}
			} else {
				<-closeRemote
			}
			if _, e := io.WriteString(ch, stdout); e != nil {
				return e
			}
			if _, e := io.WriteString(ch.Stderr(), stderr); e != nil {
				return e
			}
			if _, e := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7})); e != nil {
				return e
			}
			if err := ch.Close(); err != nil {
				return err
			}
			// Keep the SSH transport alive until the channel-close acknowledgement.
			for req := range requests {
				_ = req.Reply(false, nil)
			}
			return nil
		}()
	}()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	sshdir := filepath.Join(cfg.Paths.HomeBaseDir, utils.NormalizeUsername(current.Username), ".ssh")
	if err := os.MkdirAll(sshdir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshdir, "known_hosts"), []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(signer.PublicKey()))), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqlDB.Close() }()
	if err := db.AutoMigrate(&models.SshHostKey{}); err != nil {
		t.Fatal(err)
	}
	proxyKey, _, _, err := sshHostKey.EnsureSFTPProxyHostKey(db, false)
	if err != nil {
		t.Fatal(err)
	}
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	frontClient, frontBridge := net.Pipe()
	originalIn, originalOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inputRead, outputWrite
	finished := make(chan struct{})
	var proxyErr error
	go func() {
		proxyErr = Proxy(db, models.AccessRight{Server: "127.0.0.1", Port: port, Username: "fixture", PrivateKey: string(pem.EncodeToMemory(priv))})
		close(finished)
	}()
	defer func() {
		_ = frontClient.Close()
		_ = frontBridge.Close()
		_ = inputWrite.Close()
		_ = outputRead.Close()
		_ = inputRead.Close()
		_ = outputWrite.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("proxy failed to stop after disconnect")
		}
		os.Stdin, os.Stdout = originalIn, originalOut
	}()
	go func() { _, _ = io.Copy(inputWrite, frontBridge); _ = inputWrite.Close() }()
	go func() { _, _ = io.Copy(frontBridge, outputRead); _ = frontBridge.Close() }()
	_ = frontClient.SetDeadline(time.Now().Add(4 * time.Second))
	conn, chans, reqs, err := ssh.NewClientConn(frontClient, "fixture", &ssh.ClientConfig{User: "fixture", HostKeyCallback: ssh.FixedHostKey(proxyKey.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer func() { _ = client.Close() }()
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"shell"})); err != nil || ok {
		t.Fatalf("accepted unsupported subsystem: %t, %v", ok, err)
	}
	if ok, err := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"})); err != nil || !ok {
		t.Fatalf("SFTP request: %t %v", ok, err)
	}
	result := make(chan string, 2)
	go func() { b, _ := io.ReadAll(channel); result <- string(b) }()
	go func() { b, _ := io.ReadAll(channel.Stderr()); result <- string(b) }()
	status := make(chan uint32, 1)
	go func() {
		for req := range requests {
			if req.Type == "exit-status" {
				var payload struct{ Status uint32 }
				if ssh.Unmarshal(req.Payload, &payload) == nil {
					status <- payload.Status
				}
			}
			_ = req.Reply(false, nil)
		}
		close(status)
	}()
	if halfClose {
		if err := channel.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	} else {
		releaseRemote()
	}
	select {
	case <-finished:
		if proxyErr != nil {
			t.Fatal(proxyErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("target exited but proxy stayed blocked on client input")
	}
	for range 2 {
		select {
		case got := <-result:
			if got != stdout && got != stderr {
				t.Fatalf("truncated output: received %d bytes", len(got))
			}
		case <-time.After(time.Second):
			t.Fatal("output was not drained")
		}
	}
	if got, ok := <-status; !ok || got != 7 {
		t.Fatalf("lost target exit status: %d, present=%t", got, ok)
	}
	if err := <-backendDone; err != nil {
		t.Fatal(err)
	}
}
