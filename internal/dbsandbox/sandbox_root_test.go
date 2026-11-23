package dbsandbox

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPrepareSandboxRoot(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := prepareSandboxRoot(parent); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "gobastion-db")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0711 {
		t.Fatalf("sandbox root: info=%v, err=%v", info, err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := prepareSandboxRoot(parent); err == nil {
		t.Fatal("writable sandbox root was accepted")
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0777 {
		t.Fatalf("unsafe root was modified: info=%v, err=%v", info, err)
	}
}

func TestBoundedHostUID(t *testing.T) {
	if _, err := boundedHostUID(-1); err == nil {
		t.Fatal("negative UID accepted")
	}
	if got, err := boundedHostUID(1000); err != nil || got != 1000 {
		t.Fatalf("valid UID rejected: %d, %v", got, err)
	}
	if strconv.IntSize == 64 {
		tooLarge := int(uint64(^uint32(0)) + 1)
		if _, err := boundedHostUID(tooLarge); err == nil {
			t.Fatal("UID above uint32 accepted")
		}
	}
}

func TestPrepareSandboxRootRejectsSymlink(t *testing.T) {
	parent := t.TempDir()
	target := t.TempDir()
	for _, dir := range []string{parent, target} {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, filepath.Join(parent, "gobastion-db")); err != nil {
		t.Fatal(err)
	}
	if err := prepareSandboxRoot(parent); err == nil {
		t.Fatal("sandbox root symlink was accepted")
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("symlink target was modified: info=%v, err=%v", info, err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if err := prepareSandboxRoot(parent); err == nil {
		t.Fatal("writable runtime parent was accepted")
	}
}
