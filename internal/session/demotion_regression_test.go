package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"github.com/glebarez/sqlite"
	"goBastion/internal/config"
	bastiondb "goBastion/internal/db"
	"goBastion/internal/models"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestRegressionDemotedAdministratorCannotUseSSHOverride(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("requires unprivileged session path")
	}
	config.ResetForTesting()
	_ = config.Load()
	defer config.ResetForTesting()
	cfg := config.DefaultConfig()
	cfg.TTYRec.Enabled = false
	cfg.Splash.Enabled = false
	cfg.Paths.HomeBaseDir = t.TempDir()
	config.SetForTesting(cfg)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOB_SESSION_ID", "")
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
	sqlDB.SetMaxOpenConns(1)
	defer func() { _ = sqlDB.Close() }()
	if err := db.AutoMigrate(bastiondb.ManagedModelsInDependencyOrder()...); err != nil {
		t.Fatal(err)
	}
	actor := models.User{Username: current.Username, Role: models.RoleAdmin, Enabled: true}
	owner := models.User{Username: "other", Role: models.RoleUser, Enabled: true}
	for _, row := range []any{&actor, &owner} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := ssh.MarshalPrivateKey(private, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	key := models.SelfEgressKey{UserID: owner.ID, Type: "ed25519", PrivKey: encryptedFixture(t, string(pem.EncodeToMemory(encoded))), Fingerprint: "fixture"}
	access := models.SelfAccess{UserID: owner.ID, Server: "fixture", Port: 22, Username: "deploy", Protocol: "ssh"}
	known := models.KnownHostsEntry{UserID: actor.ID, Entry: "fixture ssh-ed25519 AAAA"}
	for _, row := range []any{&key, &access, &known} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	kh := filepath.Join(cfg.Paths.HomeBaseDir, current.Username, ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(kh), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kh, nil, 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	marker := filepath.Join(bin, "launched")
	t.Setenv("REVIEW_LAUNCH_MARKER", marker)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\ntouch \"$REVIEW_LAUNCH_MARKER\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	var fired atomic.Bool
	if err := db.Callback().Query().After("gorm:query").Register("review:demotion", func(tx *gorm.DB) {
		found, ok := tx.Statement.Dest.(*models.User)
		if !ok || found.ID != actor.ID || !fired.CompareAndSwap(false, true) {
			return
		}
		if err := db.Session(&gorm.Session{NewDB: true}).Model(&models.User{}).Where("id = ?", actor.ID).Update("role", models.RoleUser).Error; err != nil {
			t.Error(err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	old := os.Args
	os.Args = []string{"goBastion", "deploy@fixture"}
	defer func() { os.Args = old }()
	Run(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !fired.Load() {
		t.Fatal("demotion fixture did not run")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("Run launched SSH using another account's egress key after administrator demotion")
	}
}
