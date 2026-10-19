package sftpProxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils"

	"golang.org/x/crypto/ssh"
)

// Exercise the actual IPv6 dial and host-key callback. The server deliberately
// refuses SFTP after authentication, before the proxy starts using stdin/stdout.
func TestIPv6TargetHostKeyVerification(t *testing.T) {
	for _, tc := range []struct {
		name          string
		bracketed     bool
		isDefaultPort bool
		wrongKey      bool
	}{
		{name: "bare"},
		{name: "bracketed", bracketed: true},
		{name: "configured default port", isDefaultPort: true},
		{name: "changed key rejected", wrongKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Fatalf("listen on IPv6 loopback: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			port := int64(listener.Addr().(*net.TCPAddr).Port)
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(key)
			if err != nil {
				t.Fatal(err)
			}
			privatePEM, err := ssh.MarshalPrivateKey(key, "test")
			if err != nil {
				t.Fatal(err)
			}
			serverConfig := &ssh.ServerConfig{NoClientAuth: true}
			serverConfig.AddHostKey(signer)
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				server, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
				if err != nil {
					return
				}
				defer func() { _ = server.Close() }()
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					channel, requests, err := newChannel.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						_ = request.Reply(false, nil)
						if request.Type == "subsystem" {
							_ = channel.Close()
							return
						}
					}
				}
			}()

			cfg := config.DefaultConfig()
			cfg.Paths.HomeBaseDir = t.TempDir()
			if tc.isDefaultPort {
				cfg.SSH.DefaultPort = port
			}
			_ = config.Load()
			config.SetForTesting(cfg)
			t.Cleanup(config.ResetForTesting)
			current, err := user.Current()
			if err != nil {
				t.Fatal(err)
			}
			sshDir := filepath.Join(cfg.Paths.HomeBaseDir, utils.NormalizeUsername(current.Username), ".ssh")
			if err := os.MkdirAll(sshDir, 0700); err != nil {
				t.Fatal(err)
			}
			trustedKey := signer.PublicKey()
			if tc.wrongKey {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				trustedKey, err = ssh.NewPublicKey(pub)
				if err != nil {
					t.Fatal(err)
				}
			}
			entry := fmt.Sprintf("[::1]:%d %s", port, ssh.MarshalAuthorizedKey(trustedKey))
			if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(entry), 0600); err != nil {
				t.Fatal(err)
			}
			host := "::1"
			if tc.bracketed {
				host = "[::1]"
			}
			err = Proxy(nil, models.AccessRight{Server: host, Port: port, Username: "deploy",
				PrivateKey: string(pem.EncodeToMemory(privatePEM))})
			want := "request sftp subsystem:"
			if tc.wrongKey {
				want = "knownhosts: key mismatch"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("expected %q, got %v", want, err)
			}
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Fatal("test SSH server did not stop")
			}
		})
	}
}
