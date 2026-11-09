package recording

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func recoveryFixture(t *testing.T) (string, string, string, *os.File) {
	t.Helper()
	archive := privateTestArchive(t)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(archive, current.Username, "fixture")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	spool, err := os.MkdirTemp(parent, ".ssh-record-")
	if err != nil {
		t.Fatal(err)
	}
	raw := "deploy.fixture:22_2026-11-07_00-00-00.ttyrec"
	destination := filepath.Join(current.Username, "fixture", raw+".gz")
	lock, err := Prepare(spool, destination, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, raw), []byte("first\nlast\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	return archive, spool, destination, lock
}
func readGzip(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	data, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func TestRecoverySkipsActiveAndSerializesWorkers(t *testing.T) {
	archive, spool, destination, lock := recoveryFixture(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	Recover(archive, logger)
	if _, err := os.Stat(filepath.Join(archive, destination)); !os.IsNotExist(err) {
		t.Fatal("active recording was recovered")
	}
	_ = lock.Close()
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() { Recover(archive, logger) })
	}
	wg.Wait()
	if got := readGzip(t, filepath.Join(archive, destination)); got != "first\nlast\n" {
		t.Fatalf("recording truncated: %q", got)
	}
	if _, err := os.Stat(spool); !os.IsNotExist(err) {
		t.Fatalf("spool not removed: %v", err)
	}
}
func TestRecoveryRetriesUnavailableArchiveAndRecognizesCommittedCopy(t *testing.T) {
	archive, spool, destination, lock := recoveryFixture(t)
	_ = lock.Close()
	// An existing conflicting entry is never overwritten.
	if err := os.WriteFile(filepath.Join(archive, destination), []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	Recover(archive, logger)
	if !strings.Contains(logs.String(), "recording_recovery_failed") {
		t.Fatal("missing recovery error")
	}
	if _, err := os.Stat(spool); err != nil {
		t.Fatal("failed recovery removed source")
	}
	if err := os.Remove(filepath.Join(archive, destination)); err != nil {
		t.Fatal(err)
	}
	Recover(archive, logger)
	if got := readGzip(t, filepath.Join(archive, destination)); got != "first\nlast\n" {
		t.Fatal(got)
	}
	// Simulate a crash after committing the destination but before cleanup.
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimSuffix(filepath.Base(destination), ".gz")
	held, err := Prepare(spool, destination, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, raw), []byte("first\nlast\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = held.Close()
	Recover(archive, logger)
	if _, err := os.Stat(spool); !os.IsNotExist(err) {
		t.Fatal("committed recording was not cleaned up")
	}
}
func TestRecoveryRejectsSymlinksAndDestinationEscape(t *testing.T) {
	for _, attack := range []string{"raw symlink", "manifest escape", "output hardlink"} {
		t.Run(attack, func(t *testing.T) {
			archive, spool, destination, lock := recoveryFixture(t)
			_ = lock.Close()
			raw := strings.TrimSuffix(filepath.Base(destination), ".gz")
			outside := filepath.Join(t.TempDir(), "protected")
			if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			switch attack {
			case "raw symlink":
				if err := os.Remove(filepath.Join(spool, raw)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(spool, raw)); err != nil {
					t.Fatal(err)
				}
			case "manifest escape":
				data, _ := json.Marshal(Manifest{"../../escape.ttyrec.gz", raw})
				if err := os.WriteFile(filepath.Join(spool, "manifest.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			case "output hardlink":
				if err := os.Link(outside, filepath.Join(spool, ".recovery.gz.tmp")); err != nil {
					t.Fatal(err)
				}
			}
			Recover(archive, slog.New(slog.NewTextHandler(io.Discard, nil)))
			data, err := os.ReadFile(outside)
			if err != nil || string(data) != "keep" {
				t.Fatalf("recovery modified external file: %q %v", data, err)
			}
			if attack != "output hardlink" {
				if _, err := os.Stat(filepath.Join(archive, destination)); !os.IsNotExist(err) {
					t.Fatal("unsafe spool published")
				}
			}
		})
	}
}
func TestPersistentDBSpoolRecovery(t *testing.T) {
	archive := privateTestArchive(t)
	account := "alice"
	if os.Geteuid() == 0 {
		archive = rootRecoveryArchive(t, filepath.Join(t.TempDir(), "archive"), "victim")
		account = "victim"
	}
	spool, err := NewDBSpool(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(spool.Path, archive) {
		t.Fatal("DB spool is not on archive volume")
	}
	destination := filepath.Join(account, "fixture", "session.ttyrec.gz")
	lock, err := Prepare(spool.WorkPath, destination, "session.ttyrec")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool.WorkPath, "session.ttyrec"), []byte("db recording"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	spool.Close()
	Recover(archive, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := readGzip(t, filepath.Join(archive, destination)); got != "db recording" {
		t.Fatal(got)
	}
}

func TestInheritedLockProtectsRecorder(t *testing.T) {
	archive, spool, destination, lock := recoveryFixture(t)
	cmd := exec.Command("sh", "-c", "printf ready; read line")
	cmd.ExtraFiles = []*os.File{lock}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	marker := make([]byte, 5)
	if _, err := io.ReadFull(stdout, marker); err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	Recover(archive, logger)
	if _, err := os.Stat(filepath.Join(archive, destination)); !os.IsNotExist(err) {
		t.Fatal("recorder lost its inherited lock")
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err == nil {
		t.Fatal("fixture read unexpectedly succeeded")
	}
	Recover(archive, logger)
	if _, err := os.Stat(spool); !os.IsNotExist(err) {
		t.Fatal("abandoned recording was not recovered")
	}
}
func TestRecoveryAcrossOwners(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires disposable root integration container")
	}
	accounts := []string{"victim", "recording-test"}
	archive := rootRecoveryArchive(t, filepath.Join(t.TempDir(), "archive"), accounts...)
	for _, name := range accounts {
		account, err := user.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		uid, err := strconv.Atoi(account.Uid)
		if err != nil {
			t.Fatal(err)
		}
		parent := filepath.Join(archive, name, "fixture")
		spool, err := os.MkdirTemp(parent, ".ssh-record-")
		if err != nil {
			t.Fatal(err)
		}
		raw := "session.ttyrec"
		lock, err := Prepare(spool, filepath.Join(name, "fixture", raw+".gz"), raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(spool, raw), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(spool, uid, -1); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(spool, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(filepath.Join(spool, raw), uid, -1); err != nil {
			t.Fatal(err)
		}
		_ = lock.Close()
	}
	Recover(archive, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, name := range accounts {
		path := filepath.Join(archive, name, "fixture", "session.ttyrec.gz")
		if got := readGzip(t, path); got != name {
			t.Fatal(got)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		account, err := user.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if strconv.Itoa(int(stat.Uid)) != account.Uid {
			t.Fatal("recovery changed the recording owner")
		}
	}
}

func TestRecoverySkipsActivePublication(t *testing.T) {
	archive := privateTestArchive(t)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(current.Username, "fixture", ".publish-fixture")
	full := filepath.Join(archive, path)
	if err := os.MkdirAll(full, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(full, ".lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "recording.gz"), []byte("in progress"), 0600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	Recover(archive, logger)
	if _, err := os.Stat(filepath.Join(full, "recording.gz")); err != nil {
		t.Fatal("active publication was removed")
	}
	_ = lock.Close()
	Recover(archive, logger)
	if _, err := os.Stat(full); !os.IsNotExist(err) {
		t.Fatalf("abandoned publication was not cleaned: %v", err)
	}
}

func TestRecoveryRetriesTemporaryFallback(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(base, "unavailable")
	account := "alice"
	if os.Geteuid() == 0 {
		account = "victim"
	}
	destination := filepath.Join(account, "fixture", "session.ttyrec.gz")
	if err := os.WriteFile(archive, []byte("unavailable"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", t.TempDir())
	spool, err := NewDBSpool(archive)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := Prepare(spool.WorkPath, destination, "session.ttyrec")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool.WorkPath, "session.ttyrec"), []byte("fallback"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = lock.Close()
	spool.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	Recover(archive, logger)
	if _, err := os.Stat(filepath.Join(spool.Path, "session.ttyrec")); err != nil {
		t.Fatal("failed retry removed raw recording")
	}
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		rootRecoveryArchive(t, archive, "victim")
	} else if err := os.Mkdir(archive, 0700); err != nil {
		t.Fatal(err)
	}
	Recover(archive, logger)
	if got := readGzip(t, filepath.Join(archive, destination)); got != "fallback" {
		t.Fatal(got)
	}
}

// rootRecoveryArchive models the production archive layout. The caller's
// disposable test parent is root-owned and private; no real archive is touched.
func rootRecoveryArchive(t *testing.T, archive string, accounts ...string) string {
	t.Helper()
	group, err := recordingGroupID("gobastion")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(archive, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(archive, 0, group); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archive, 0751); err != nil {
		t.Fatal(err)
	}
	for _, name := range accounts {
		if err := ProvisionAccount(archive, name); err != nil {
			t.Fatal(err)
		}
		uid, err := recordingUsernameUID(name)
		if err != nil {
			t.Fatal(err)
		}
		base, err := openArchiveDirectory(archive, ".", uid)
		if err != nil {
			t.Fatal(err)
		}
		server, err := openArchiveSubdirectory(base, filepath.Join(name, "fixture"), uid)
		_ = base.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return archive
}
