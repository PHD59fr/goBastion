package sshConnector

import (
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/glebarez/sqlite"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"gorm.io/gorm"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHRecordingPublication(t *testing.T) {
	for _, tc := range []struct {
		publicationFailure bool
		recorderExit       int
	}{
		{publicationFailure: false},
		{publicationFailure: true},
		{recorderExit: 255},
	} {
		t.Run(fmt.Sprintf("publish_failure_%t_exit_%d", tc.publicationFailure, tc.recorderExit), func(t *testing.T) {
			testSSHRecordingPublication(t, tc.publicationFailure, tc.recorderExit)
		})
	}
}
func testSSHRecordingPublication(t *testing.T, failure bool, recorderExit int) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Paths.HomeBaseDir = t.TempDir()
	cfg.Paths.TtyrecDir = t.TempDir()
	if err := os.Chmod(cfg.Paths.TtyrecDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.TTYRec.Enabled = true
	config.SetForTesting(cfg)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOB_SESSION_ID", "")
	t.Setenv("GOB_TEST_RECORD_PARENT", filepath.Join(cfg.Paths.TtyrecDir, "alice", "fixture.example"))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.KnownHostsEntry{}); err != nil {
		t.Fatal(err)
	}
	u := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.KnownHostsEntry{UserID: u.ID, Entry: "fixture.example ssh-ed25519 AAAA"}).Error; err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(cfg.Paths.HomeBaseDir, "alice", ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(kh), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kh, nil, 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	script := `#!/bin/sh
printf 'recorded-session' > "$2"
`
	if failure {
		script += `mkdir "$GOB_TEST_RECORD_PARENT/$(basename "$2").gz"` + "\n"
	}
	if recorderExit != 0 {
		script += fmt.Sprintf("exit %d\n", recorderExit)
	}
	if err := os.WriteFile(filepath.Join(bin, "ttyrec"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	err = SshConnection(db, u, models.AccessRight{Server: "fixture.example", Username: "deploy", Port: 22, PrivateKey: "fixture"})
	if failure && (err == nil || !strings.Contains(err.Error(), "publishing gzip")) {
		t.Fatalf("expected publication failure, got %v", err)
	}
	if !failure && recorderExit == 0 && err != nil {
		t.Fatal(err)
	}
	if recorderExit != 0 {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != recorderExit {
			t.Fatalf("recorded command error lost exit status %d: %v", recorderExit, err)
		}
	}
	var saved []string
	if err := filepath.WalkDir(cfg.Paths.TtyrecDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			saved = append(saved, path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := 1
	if failure {
		want = 4
	}
	if len(saved) != want {
		t.Fatalf("recording files=%v, want %d", saved, want)
	}
	for _, path := range saved {
		if filepath.Base(path) == ".lock" || filepath.Base(path) == "manifest.json" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(path, ".ttyrec") {
			if string(data) != "recorded-session" {
				t.Fatal("raw recording corrupted")
			}
		} else {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := gzip.NewReader(f)
			if err != nil {
				_ = f.Close()
				t.Fatal(err)
			}
			content, err := io.ReadAll(reader)
			_ = reader.Close()
			_ = f.Close()
			if err != nil || string(content) != "recorded-session" {
				t.Fatalf("invalid compressed recording: %q %v", content, err)
			}
		}
		if failure {
			info, err := os.Stat(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0700 {
				t.Fatalf("spool permissions=%o", info.Mode().Perm())
			}
		}
	}
	if !failure {
		entries, err := os.ReadDir(filepath.Dir(saved[0]))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), ".ssh-record-") {
				spoolEntries, err := os.ReadDir(filepath.Join(filepath.Dir(saved[0]), entry.Name()))
				if err != nil || len(spoolEntries) != 0 {
					t.Fatalf("spool not empty: %v, %v", spoolEntries, err)
				}
			} else if entry.Name() != filepath.Base(saved[0]) {
				t.Fatalf("unexpected recording entry: %s", entry.Name())
			}
		}
	}
}
