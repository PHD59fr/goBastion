package dbConnector

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"
)

func TestRecordingSurvivesPublicationFailure(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	base := t.TempDir()
	spool := filepath.Join(base, "spool")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", spool)
	capture := filepath.Join(base, "recording-path")
	t.Setenv("REVIEW_RECORDING_PATH", capture)
	t.Setenv("PATH", base+":"+os.Getenv("PATH"))
	script := "#!/bin/sh\nprintf '%s' \"$2\" > \"$REVIEW_RECORDING_PATH\"\nprintf 'AUDIT_RECORDING_MARKER' > \"$2\"\nshift 3\nexec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(base, "ttyrec"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.TTYRec.Enabled = true
	cfg.Paths.TtyrecDir = filepath.Join(base, "archive")
	if err := os.WriteFile(cfg.Paths.TtyrecDir, []byte("fixture destination unavailable"), 0600); err != nil {
		t.Fatal(err)
	}
	config.SetForTesting(cfg)
	original := sandboxCommand
	t.Cleanup(func() { sandboxCommand = original })
	sandboxCommand = func(ctx context.Context, _ string, _ int64, _ string, _, _ []string) (*exec.Cmd, func(), error) {
		cmd := exec.CommandContext(ctx, "/bin/true")
		cmd.Env = os.Environ()
		return cmd, func() {}, nil
	}
	err := Connect(nil, models.User{Username: "alice"}, models.DBAccessRight{Host: "fixture", Port: 3306, Protocol: "mysql", Username: "reader"})
	if err == nil || !strings.Contains(err.Error(), "publish DB recording") {
		t.Fatalf("fixture did not reach publication failure: %v", err)
	}
	path, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Dir(string(path))); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("recovery spool is not private: %v %v", info, err)
	}
	raw, err := os.ReadFile(string(path))
	if err != nil || string(raw) != "AUDIT_RECORDING_MARKER" {
		t.Fatalf("publication failed and the raw recording was lost: %q %v", raw, err)
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(string(path)), "*.gz.tmp"))
	if err != nil || len(files) != 1 {
		t.Fatalf("compressed recovery copy missing: %v %v", files, err)
	}
	f, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	compressed, err := io.ReadAll(gz)
	if err != nil || string(compressed) != string(raw) {
		t.Fatalf("compressed recording is incomplete: %q %v", compressed, err)
	}
}

func TestFailedPublicationRemovesIncompleteDestination(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Paths.TtyrecDir = t.TempDir()
	config.SetForTesting(cfg)
	// Reading a directory fails after the destination has been created. A
	// retry must not be blocked by an empty/corrupt exclusive archive entry.
	relative := "alice/fixture/session.ttyrec.gz"
	if err := publishRecording(t.TempDir(), relative); err == nil {
		t.Fatal("expected copy failure")
	}
	if _, err := os.Stat(filepath.Join(cfg.Paths.TtyrecDir, relative)); !os.IsNotExist(err) {
		t.Fatalf("incomplete archive entry remains: %v", err)
	}
}
