package self

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	cmdssh "goBastion/internal/commands/ssh"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/commandline"
	"golang.org/x/crypto/ssh"
)

func TestSSHUsernameCannotBecomeLocalOption(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Paths.HomeBaseDir = t.TempDir()
	cfg.TTYRec.Enabled = false
	cfg.Session.MaxSessionDuration = config.Duration(2 * time.Second)
	config.SetForTesting(cfg)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("EGRESS_ENC_KEY", "")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nexec /usr/bin/ssh -F /dev/null \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	db := newTestDB(t)
	u := newRegularUser(t, db, "alice")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	key := models.SelfEgressKey{UserID: u.ID, Type: "ed25519", PrivKey: string(pem.EncodeToMemory(block)), Fingerprint: "fixture"}
	if err := db.Create(&key).Error; err != nil {
		t.Fatal(err)
	}
	host := "fixture.example"
	if err := db.Create(&models.KnownHostsEntry{UserID: u.ID, Entry: host + " ssh-ed25519 AAAA"}).Error; err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(cfg.Paths.HomeBaseDir, "alice", ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(kh), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kh, nil, 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "LOCAL_COMMAND_RAN")
	username := "-oProxyCommand=touch " + marker + ";#"
	if err := AddAccess(db, u, []string{"--server", host, "--username", username, "--force"}); err != nil {
		t.Fatalf("access creation rejected input: %v", err)
	}
	err = cmdssh.Connect(db, *u, *slog.New(slog.NewTextHandler(io.Discard, nil)), commandline.Quote(username+"@"+host)+" localhost")
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatalf("a personal access username executed a local shell command in the bastion process context; Connect returned %v", err)
	}
	t.Logf("Connect returned %v", err)
}
