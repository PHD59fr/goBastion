package recording

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSSHSpoolRenameSubstitution(t *testing.T) {
	testSSHSpoolSwap(t, privateTestArchive(t), false)
}

// TestRootSSHSpool uses a second UID and must run in a disposable root environment.
func TestRootSSHSpool(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_SPOOL") != "1" {
		t.Skip("requires disposable root environment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	root, err := os.MkdirTemp("/run", "gobastion-ssh-spool-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	testSSHSpoolSwap(t, root, true)
	foreign := filepath.Join(root, "foreign")
	if err := os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(foreign, 1001, 1001); err != nil {
		t.Fatal(err)
	}
	parent, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(parent) }()
	if fd, err := openSSHSpool(parent, "foreign"); err == nil {
		_ = unix.Close(fd)
		t.Fatal("foreign-owned replacement accepted")
	}
}

func testSSHSpoolSwap(t *testing.T, root string, differentUID bool) {
	t.Helper()
	parent := filepath.Join(root, "shared")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if differentUID {
		if err := os.Chmod(root, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0770); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(parent, 0, 1001); err != nil {
			t.Fatal(err)
		}
	}
	victim := filepath.Join(root, "victim")
	if err := os.Mkdir(victim, 0700); err != nil {
		t.Fatal(err)
	}
	victimFile := filepath.Join(victim, "raw")
	if err := os.WriteFile(victimFile, []byte("victim"), 0600); err != nil {
		t.Fatal(err)
	}
	parentFile, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := newSSHSpoolAt(parentFile, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = spool.Close(false) }()
	moved := spool.Path + "-moved"
	if differentUID {
		cmd := exec.Command("/bin/sh", "-c", `mv -- "$1" "$2" && ln -s -- "$3" "$1"`, "swap", spool.Path, moved, victim)
		cmd.Env = []string{}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1001, Gid: 1001}}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("swap: %v: %s", err, out)
		}
	} else {
		if err := os.Rename(spool.Path, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, spool.Path); err != nil {
			t.Fatal(err)
		}
	}
	lock, err := Prepare(spool.WorkPath, "shared/result.gz", "raw")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := os.WriteFile(filepath.Join(spool.WorkPath, "raw"), []byte("recording"), 0600); err != nil {
		t.Fatal(err)
	}
	publicationRoot := root
	if differentUID {
		publicationRoot = filepath.Join(root, "private-archive")
		if err := os.Mkdir(publicationRoot, 0700); err != nil {
			t.Fatal(err)
		}
	}
	destination := "shared/result.gz"
	if differentUID {
		destination = "result.gz"
	}
	if err := Publish(publicationRoot, filepath.Join(spool.WorkPath, "raw"), destination, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{victimFile: "victim", filepath.Join(moved, "raw"): "recording", filepath.Join(publicationRoot, destination): "recording"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", path, got, err, want)
		}
	}
	if err := spool.Close(true); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(victimFile); err != nil || string(got) != "victim" {
		t.Fatalf("cleanup changed victim: %q, %v", got, err)
	}
	if _, err := os.Lstat(spool.Path); err != nil {
		t.Fatalf("substitute removed: %v", err)
	}
}

func TestSSHSpoolRejectsReplacementBeforeOpen(t *testing.T) {
	parent := t.TempDir()
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := os.Symlink(t.TempDir(), filepath.Join(parent, "candidate")); err != nil {
		t.Fatal(err)
	}
	if got, err := openSSHSpool(fd, "candidate"); err == nil {
		_ = unix.Close(got)
		t.Fatal("symlink accepted")
	}
	if err := os.Remove(filepath.Join(parent, "candidate")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, "candidate"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(parent, "candidate"), 0755); err != nil {
		t.Fatal(err)
	}
	if got, err := openSSHSpool(fd, "candidate"); err == nil {
		_ = unix.Close(got)
		t.Fatal("insecure directory accepted")
	}
}
