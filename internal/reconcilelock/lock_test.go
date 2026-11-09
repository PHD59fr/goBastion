package reconcilelock

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockProcess(t *testing.T) {
	base := os.Getenv("RECONCILE_TEST_BASE")
	if base == "" {
		return
	}
	release, err := acquire(context.Background(), base, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	state, err := os.ReadFile(filepath.Join(base, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, os.Getenv("RECONCILE_TEST_RESULT")), state, 0600); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("RECONCILE_TEST_WAIT") == "1" {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(base, "continue")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for release")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func awaitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func TestSeparateProcessesSnapshotAfterLock(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "state"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	start := func(result string, wait bool) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLockProcess$")
		cmd.Env = append(os.Environ(), "RECONCILE_TEST_BASE="+base, "RECONCILE_TEST_RESULT="+result)
		if wait {
			cmd.Env = append(cmd.Env, "RECONCILE_TEST_WAIT=1")
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		return cmd
	}
	old := start("old-result", true)
	awaitFile(t, filepath.Join(base, "old-result"))
	newer := start("new-result", false)
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(base, "new-result")); !os.IsNotExist(err) {
		t.Fatal("second process proceeded while lock held")
	}
	if err := os.WriteFile(filepath.Join(base, "state"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "continue"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := old.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := newer.Wait(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(base, "new-result"))
	if err != nil || string(got) != "new" {
		t.Fatalf("snapshot = %q, %v", got, err)
	}
}

func TestCancellationAndRelease(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	release, err := acquire(context.Background(), base, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := acquire(ctx, base, uint32(os.Geteuid())); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	release, err = acquire(context.Background(), base, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectUnsafePaths(t *testing.T) {
	for _, tc := range []string{"base-mode", "base-owner", "directory-symlink", "directory-mode", "file-symlink", "file-mode", "file-hardlink"} {
		t.Run(tc, func(t *testing.T) {
			base := t.TempDir()
			if err := os.Chmod(base, 0700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(base, "gobastion")
			uid := uint32(os.Geteuid())
			switch tc {
			case "base-mode":
				if err := os.Chmod(base, 0777); err != nil {
					t.Fatal(err)
				}
			case "base-owner":
				uid++
			case "directory-symlink":
				if err := os.Symlink(base, dir); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(dir, "reconcile.lock")
				switch tc {
				case "directory-mode":
					if err := os.Chmod(dir, 0777); err != nil {
						t.Fatal(err)
					}
				case "file-symlink":
					if err := os.Symlink(filepath.Join(base, "target"), file); err != nil {
						t.Fatal(err)
					}
				case "file-mode":
					if err := os.WriteFile(file, nil, 0644); err != nil {
						t.Fatal(err)
					}
				case "file-hardlink":
					if err := os.WriteFile(file, nil, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Link(file, filepath.Join(base, "other")); err != nil {
						t.Fatal(err)
					}
				}
			}
			release, err := acquire(context.Background(), base, uid)
			if err == nil {
				_ = release()
				t.Fatal("unsafe path accepted")
			}
			if strings.Contains(err.Error(), "deadline") {
				t.Fatal(err)
			}
		})
	}
}

// TestProductionRootLock is opt-in for a disposable root environment only.
func TestProductionRootLock(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_RECONCILE_LOCK") != "1" {
		t.Skip("requires disposable root environment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("production lock test requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	release, err := Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}
