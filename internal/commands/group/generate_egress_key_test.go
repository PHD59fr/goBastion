package group

import (
	"os"
	"path/filepath"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"
)

func TestKeyGenerationPreservesOtherSessionFiles(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	base := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Paths.HomeBaseDir = base
	config.SetForTesting(cfg)
	dir := filepath.Join(base, "audit", ".tmp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	activeKey := filepath.Join(dir, "sshkey-active-session.pem")
	if err := os.WriteFile(activeKey, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "ssh-keygen"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	db := newTestDB(t)
	admin := newAdminUser(t, db, "audit")
	g := models.Group{Name: "fixture"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatal(err)
	}
	_ = GenerateEgressKey(db, admin, []string{"--group", "fixture"})
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary operation files left behind: %v %v", entries, err)
	}
	if _, err := os.Stat(activeKey); err != nil {
		t.Fatalf("generating a key removed another session's temporary key: %v", err)
	}
}
