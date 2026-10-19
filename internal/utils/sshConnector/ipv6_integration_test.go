package sshConnector

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// Use the real OpenSSH and ssh-keyscan binaries through the production
// connector, including TOFU, the egress key and a successful remote command.
func TestSshConnectionIPv6WithOpenSSH(t *testing.T) {
	sshBinary, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is not installed")
	}
	if _, err := exec.LookPath("ssh-keyscan"); err != nil {
		t.Skip("ssh-keyscan is not installed")
	}
	for _, host := range []string{"::1", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			listener, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			_, hostKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(hostKey)
			if err != nil {
				t.Fatal(err)
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			expectedKey, err := ssh.NewPublicKey(public)
			if err != nil {
				t.Fatal(err)
			}
			serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if bytes.Equal(key.Marshal(), expectedKey.Marshal()) {
					return nil, nil
				}
				return nil, fmt.Errorf("unexpected client key")
			}}
			serverConfig.AddHostKey(signer)
			var commands atomic.Int32
			var handlers sync.WaitGroup
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					handlers.Add(1)
					go func() {
						defer handlers.Done()
						defer func() { _ = conn.Close() }()
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						server, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
						if err != nil {
							return // ssh-keyscan disconnects before authentication.
						}
						defer func() { _ = server.Close() }()
						go ssh.DiscardRequests(requests)
						for newChannel := range channels {
							channel, requests, err := newChannel.Accept()
							if err != nil {
								return
							}
							for request := range requests {
								if request.Type == "exec" {
									commands.Add(1)
									_ = request.Reply(true, nil)
									_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
									_ = channel.Close()
									return
								}
								_ = request.Reply(false, nil)
							}
						}
					}()
				}
			}()
			t.Cleanup(func() { _ = listener.Close(); <-acceptDone; handlers.Wait() })
			dir := t.TempDir()
			cfg := config.DefaultConfig()
			cfg.Paths.HomeBaseDir = dir
			cfg.TTYRec.Enabled = false
			cfg.Session.IdleTimeout = 0
			cfg.Session.MaxSessionDuration = config.Duration(10 * time.Second)
			_ = config.Load()
			config.SetForTesting(cfg)
			t.Cleanup(config.ResetForTesting)
			t.Setenv("HOME", dir)
			t.Setenv("TEST_OPENSSH", sshBinary)
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			// Isolate this local test from the developer's ~/.ssh/config and agent.
			wrapper := "#!/bin/sh\nexec \"$TEST_OPENSSH\" -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes \"$@\"\n"
			if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(wrapper), 0700); err != nil {
				t.Fatal(err)
			}
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.AutoMigrate(&models.User{}, &models.KnownHostsEntry{}); err != nil {
				t.Fatal(err)
			}
			current, err := osuser.Current()
			if err != nil {
				t.Fatal(err)
			}
			user := models.User{Username: current.Username, Role: models.RoleUser, Enabled: true}
			if err := db.Create(&user).Error; err != nil {
				t.Fatal(err)
			}
			privatePEM, err := ssh.MarshalPrivateKey(private, "test")
			if err != nil {
				t.Fatal(err)
			}
			access := models.AccessRight{Server: host, Port: int64(listener.Addr().(*net.TCPAddr).Port),
				Username: "deploy", PrivateKey: string(pem.EncodeToMemory(privatePEM)), RemoteCmd: "true"}
			if err := SshConnection(db, user, access); err != nil {
				t.Fatal(err)
			}
			if commands.Load() != 1 {
				t.Fatalf("remote command did not execute: count=%d", commands.Load())
			}
		})
	}
}
