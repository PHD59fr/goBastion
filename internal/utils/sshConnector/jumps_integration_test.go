package sshConnector

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

func TestJumpConnectionsUseSelectedIdentity(t *testing.T) {
	native, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH unavailable")
	}
	for _, tc := range []struct {
		name  string
		hops  int
		wrong bool
	}{{"one hop", 1, false}, {"two hops", 2, false}, {"changed host key", 1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			config.ResetForTesting()
			_ = config.Load()
			defer config.ResetForTesting()
			cfg := config.DefaultConfig()
			cfg.TTYRec.Enabled = false
			cfg.Paths.HomeBaseDir = t.TempDir()
			cfg.Session.MaxSessionDuration = config.Duration(8 * time.Second)
			config.SetForTesting(cfg)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("SSH_ASKPASS", "/bin/false")
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			var executed atomic.Int64
			var listeners []net.Listener
			var known []string
			for range tc.hops + 1 {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				listeners = append(listeners, listener)
				t.Cleanup(func() { _ = listener.Close() })
				_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
				if err != nil {
					t.Fatal(err)
				}
				trusted := hostSigner.PublicKey()
				if tc.wrong && len(listeners) == 1 {
					trusted = identity.PublicKey()
				}
				known = append(known, fmt.Sprintf("[%s]:%d %s", listener.Addr().(*net.TCPAddr).IP, listener.Addr().(*net.TCPAddr).Port, ssh.MarshalAuthorizedKey(trusted)))
				go serveJumpFixture(listener, hostSigner, identity.PublicKey(), &executed)
			}
			current, err := user.Current()
			if err != nil {
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
			if err := db.AutoMigrate(&models.User{}, &models.KnownHostsEntry{}); err != nil {
				t.Fatal(err)
			}
			actor := models.User{Username: current.Username, Role: models.RoleUser, Enabled: true}
			if err := db.Create(&actor).Error; err != nil {
				t.Fatal(err)
			}
			for _, line := range known {
				if err := db.Create(&models.KnownHostsEntry{UserID: actor.ID, Entry: strings.TrimSpace(line)}).Error; err != nil {
					t.Fatal(err)
				}
			}
			kh := filepath.Join(cfg.Paths.HomeBaseDir, current.Username, ".ssh", "known_hosts")
			if err := os.MkdirAll(filepath.Dir(kh), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(kh, []byte(strings.Join(known, "")), 0600); err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			t.Setenv("TEST_OPENSSH", native)
			if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nexec \"$TEST_OPENSSH\" -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes \"$@\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			block, err := ssh.MarshalPrivateKey(private, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			access := models.AccessRight{Server: "127.0.0.1", Port: int64(listeners[tc.hops].Addr().(*net.TCPAddr).Port), Username: "deploy", PrivateKey: string(pem.EncodeToMemory(block)), RemoteCmd: "true"}
			for _, listener := range listeners[:tc.hops] {
				access.JumpHosts = append(access.JumpHosts, "deploy@"+listener.Addr().String())
			}
			err = SshConnection(db, actor, access)
			if tc.wrong {
				if err == nil || executed.Load() != 0 {
					t.Fatalf("changed jump key accepted: %v", err)
				}
			} else if err != nil || executed.Load() != 1 {
				t.Fatalf("jump failed: executions=%d err=%v", executed.Load(), err)
			}
		})
	}
}
func serveJumpFixture(listener net.Listener, host ssh.Signer, identity ssh.PublicKey, executed *atomic.Int64) {
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = raw.Close() }()
			_ = raw.SetDeadline(time.Now().Add(12 * time.Second))
			cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
				if string(pub.Marshal()) == string(identity.Marshal()) {
					return nil, nil
				}
				return nil, fmt.Errorf("wrong identity")
			}}
			cfg.AddHostKey(host)
			conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			go ssh.DiscardRequests(reqs)
			for incoming := range chans {
				ch, requests, err := incoming.Accept()
				if err != nil {
					return
				}
				if incoming.ChannelType() == "direct-tcpip" {
					var target struct {
						Host       string
						Port       uint32
						Origin     string
						OriginPort uint32
					}
					if ssh.Unmarshal(incoming.ExtraData(), &target) != nil {
						_ = ch.Close()
						continue
					}
					remote, err := net.DialTimeout("tcp", net.JoinHostPort(target.Host, fmt.Sprint(target.Port)), time.Second)
					if err != nil {
						_ = ch.Close()
						continue
					}
					go ssh.DiscardRequests(requests)
					go func() {
						defer func() { _ = ch.Close(); _ = remote.Close() }()
						upload := make(chan struct{})
						go func() { _, _ = io.Copy(remote, ch); _ = remote.(*net.TCPConn).CloseWrite(); close(upload) }()
						_, _ = io.Copy(ch, remote)
						_ = ch.Close()
						_ = remote.Close()
						<-upload
					}()
				} else {
					for req := range requests {
						if req.Type == "exec" {
							executed.Add(1)
							_ = req.Reply(true, nil)
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							_ = ch.Close()
							break
						}
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
	}
}
