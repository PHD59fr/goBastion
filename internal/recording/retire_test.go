package recording

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRootRecordingAccountRetirement(t *testing.T) {
	if os.Getenv("GOB_TEST_RECORDING_EXPOSURE_AUDIT") != "1" {
		t.Skip("requires disposable root exposure audit")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root in dedicated container")
	}
	base, err := os.MkdirTemp("/run", "gobastion-retirement-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	if err = os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(base, "archive")
	if err = os.Mkdir(archive, 0751); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(archive, 0, 1001); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(archive, 0751); err != nil {
		t.Fatal(err)
	}
	if err = ProvisionAccount(archive, "victim"); err != nil {
		t.Fatal(err)
	}
	runRecordingExposureHelper(t, 1000, "publish", archive)
	path := filepath.Join(archive, "victim/server/session.ttyrec.gz")
	if got := runRecordingExposureHelper(t, 1000, "read", path); got != "ACCESS_GRANTED" {
		t.Fatal("fixture unreadable:", got)
	}
	spool, err := NewDBSpool(archive)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := Prepare(spool.WorkPath, "victim/server/pending.ttyrec.gz", "session.ttyrec")
	if err != nil {
		t.Fatal(err)
	}
	if err = RetireAccount(archive, "victim"); err == nil {
		t.Fatal("retired account with pending DB capture")
	}
	_ = lock.Close()
	spool.Close()
	if err = os.RemoveAll(spool.Path); err != nil {
		t.Fatal(err)
	}
	if err = RetireAccount(archive, "victim"); err != nil {
		t.Fatal(err)
	}
	if err = RetireAccount(archive, "victim"); err != nil {
		t.Fatal("retirement not idempotent:", err)
	}
	if got := runRecordingExposureHelper(t, 1000, "read", path); got != "ACCESS_DENIED" {
		t.Fatal("recycled UID can read history:", got)
	}
	if got := runRecordingExposureHelper(t, 1004, "read", path); got != "ACCESS_GRANTED" {
		t.Fatal("administrator lost historical playback:", got)
	}
	if err = ProvisionAccount(archive, "victim"); err == nil {
		t.Fatal("retired namespace was reused")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Sys().(*syscall.Stat_t).Uid != 1000 {
		t.Fatal("retirement recursively changed record ownership")
	}
}

func TestRootRecordingAccountAbsentArchiveRetirement(t *testing.T) {
	if os.Getenv("GOB_TEST_RECORDING_EXPOSURE_AUDIT") != "1" {
		t.Skip("requires disposable root exposure audit")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root in dedicated container")
	}
	// A wrapped ENOENT from descriptor-relative traversal is an absent namespace,
	// not an existing unsafe archive. No recording data may be silently skipped.
	retired, err := IsRetiredAccount(filepath.Join(t.TempDir(), "absent", "archive"), "former")
	if err != nil || retired {
		t.Fatalf("missing archive: retired=%t error=%v", retired, err)
	}
}
