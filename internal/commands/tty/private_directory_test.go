package tty

import (
	"goBastion/internal/config"
	"goBastion/internal/models"
	"os"
	"path/filepath"
	"testing"
)

func TestRegressionPrivatePublicationDoesNotHideArchive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary playback permissions")
	}
	base := t.TempDir()
	host := filepath.Join(base, "fixture")
	if err := os.Mkdir(host, 0700); err != nil {
		t.Fatal(err)
	}
	name := "deploy.fixture:22_2026-11-07_00-00-00.ttyrec.gz"
	expected := filepath.Join(host, name)
	if err := os.WriteFile(expected, nil, 0600); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(host, ".publish-fixture")
	if err := os.Mkdir(private, 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(private, 0700) }()
	found, err := findRecordingFile(base, name)
	if err != nil || found != expected {
		t.Fatalf("a private staging directory blocks an existing archive: found=%q err=%v", found, err)
	}
}

func TestListSkipsPrivateRecoveryDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary file permissions")
	}
	config.ResetForTesting()
	_ = config.Load()
	defer config.ResetForTesting()
	cfg := config.DefaultConfig()
	cfg.Paths.TtyrecDir = t.TempDir()
	config.SetForTesting(cfg)
	actor := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	host := filepath.Join(cfg.Paths.TtyrecDir, "alice", "fixture")
	if err := os.MkdirAll(host, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".publish-fixture", ".ssh-record-fixture", ".db-pending"} {
		path := filepath.Join(host, name)
		if err := os.Mkdir(path, 0000); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(path, 0700) }()
	}
	if err := os.WriteFile(filepath.Join(host, "deploy.fixture:22_2026-11-07_00-00-00.ttyrec.gz"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := List(nil, &actor, nil); err != nil {
		t.Fatalf("private directory blocked listing: %v", err)
	}
}
