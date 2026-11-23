package recording

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func completionFixture(t *testing.T) (*os.File, *RecorderCompletion) {
	t.Helper()
	spool := t.TempDir()
	lock, err := Prepare(spool, "account/server/session.ttyrec.gz", filepath.Join(spool, "session.ttyrec"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	completion, err := ConfigureRecorder(&exec.Cmd{}, lock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(completion.Close)
	return lock, completion
}

func assertSpoolLockHeld(t *testing.T, lock *os.File) {
	t.Helper()
	probe, err := os.OpenFile(lock.Name(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("spool exclusion lock was released during finalization: %v", err)
	}
}

func TestRecorderCompletionWaitsWithoutReleasingSpoolLock(t *testing.T) {
	lock, completion := completionFixture(t)
	fd, err := unix.Dup(int(completion.writer.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	holder := os.NewFile(uintptr(fd), "recorder-descendant")
	closed := make(chan struct{})
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = holder.Close()
		close(closed)
	}()
	started := time.Now()
	finished := make(chan error, 1)
	go func() { finished <- completion.Wait(time.Second) }()
	time.Sleep(25 * time.Millisecond)
	assertSpoolLockHeld(t, lock)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 125*time.Millisecond {
		t.Fatalf("completion reported while descendant still held pipe: %v", elapsed)
	}
	<-closed
	assertSpoolLockHeld(t, lock)
}

func TestRecorderCompletionTimeoutKeepsSpoolLocked(t *testing.T) {
	lock, completion := completionFixture(t)
	fd, err := unix.Dup(int(completion.writer.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	holder := os.NewFile(uintptr(fd), "recorder-descendant")
	defer func() { _ = holder.Close() }()
	if err := completion.Wait(50 * time.Millisecond); err == nil {
		t.Fatal("live recorder descendant was accepted")
	}
	assertSpoolLockHeld(t, lock)
}
