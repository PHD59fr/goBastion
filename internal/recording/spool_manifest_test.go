package recording

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareRejectsManifestSymlink(t *testing.T) {
	spool := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(spool, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if lock, err := Prepare(spool, "account/server/recording.gz", "recording.raw"); err == nil {
		_ = lock.Close()
		t.Fatal("manifest symlink was accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "untouched" {
		t.Fatalf("manifest symlink target changed: %q, %v", data, err)
	}
}
