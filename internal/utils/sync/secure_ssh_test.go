package sync

import (
	"io"
	"log/slog"
	"os"
	osuser "os/user"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func secureTestHome(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "fixture")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	return base, home
}

func TestSecureSSHPublicationAndRenameRace(t *testing.T) {
	base, home := secureTestHome(t)
	victim := t.TempDir()
	target := filepath.Join(victim, "authorized_keys")
	if err := os.WriteFile(target, []byte("victim"), 0600); err != nil {
		t.Fatal(err)
	}
	dir, uid, gid, err := secureSSHDirAt(base, "fixture", os.Geteuid(), os.Getegid(), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dir) }()
	ssh := filepath.Join(home, ".ssh")
	if err := os.Rename(ssh, filepath.Join(home, "oldssh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, ssh); err != nil {
		t.Fatal(err)
	}
	if err := publishSSHFile(dir, uid, gid, "authorized_keys", []byte("own")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "victim" {
		t.Fatalf("victim modified: %q, %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(home, "oldssh", "authorized_keys"))
	if err != nil || string(got) != "own" {
		t.Fatalf("publication: %q, %v", got, err)
	}
	st, err := os.Stat(filepath.Join(home, "oldssh", "authorized_keys"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("file mode: %v, %v", st, err)
	}
}

func TestSecureSSHRejectsUntrustedPaths(t *testing.T) {
	for _, tc := range []string{"base-symlink", "base-mode", "base-owner", "home-symlink", "home-mode", "home-owner", "ssh-symlink", "ssh-mode", "ssh-owner"} {
		t.Run(tc, func(t *testing.T) {
			base, home := secureTestHome(t)
			trustedUID := uint32(os.Geteuid())
			uid, gid := os.Geteuid(), os.Getegid()
			switch tc {
			case "base-symlink":
				link := filepath.Join(t.TempDir(), "base")
				if err := os.Symlink(base, link); err != nil {
					t.Fatal(err)
				}
				base = link
			case "base-mode":
				if err := os.Chmod(base, 0777); err != nil {
					t.Fatal(err)
				}
			case "base-owner":
				trustedUID++
			case "home-symlink":
				if err := os.Remove(home); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), home); err != nil {
					t.Fatal(err)
				}
			case "home-mode":
				if err := os.Chmod(home, 0777); err != nil {
					t.Fatal(err)
				}
			case "home-owner":
				uid++
			default:
				ssh := filepath.Join(home, ".ssh")
				if tc == "ssh-symlink" {
					if err := os.Symlink(t.TempDir(), ssh); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(ssh, 0700); err != nil {
						t.Fatal(err)
					}
					if tc == "ssh-mode" {
						if err := os.Chmod(ssh, 0777); err != nil {
							t.Fatal(err)
						}
					} else { // The home remains valid, while a trusted-UID mismatch tests the same owner guard.
						if err := checkSSHDirOwnerMismatch(ssh); err != nil {
							t.Fatal(err)
						}
						return
					}
				}
			}
			dir, _, _, err := secureSSHDirAt(base, "fixture", uid, gid, trustedUID)
			if err == nil {
				_ = unix.Close(dir)
				t.Fatal("untrusted path accepted")
			}
		})
	}
}

func checkSSHDirOwnerMismatch(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if checkSSHDir(fd, uint32(os.Geteuid()+1), true) == nil {
		return os.ErrPermission
	}
	return nil
}

func TestTrustedHomeBaseTraversal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := os.Mkdir(filepath.Join(root, "parent"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "parent", "base"), 0700); err != nil {
		t.Fatal(err)
	}
	base, err := openTrustedBaseFrom(fd, "parent/base", uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(base)
	if err := os.Symlink("parent", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if base, err = openTrustedBaseFrom(fd, "link/base", uint32(os.Geteuid())); err == nil {
		_ = unix.Close(base)
		t.Fatal("intermediate symlink accepted")
	}
	if err := os.Chmod(filepath.Join(root, "parent"), 0777); err != nil {
		t.Fatal(err)
	}
	if base, err = openTrustedBaseFrom(fd, "parent/base", uint32(os.Geteuid())); err == nil {
		_ = unix.Close(base)
		t.Fatal("writable intermediate directory accepted")
	}
}

// TestRootLinuxSSHPublication runs only in a disposable root environment.
func TestRootLinuxSSHPublication(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_PUBLISH") != "1" {
		t.Skip("requires disposable root environment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	base, err := os.MkdirTemp("/run", "gobastion-ssh-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "fixture")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, 1001, 1001); err != nil {
		t.Fatal(err)
	}
	db, cfg := newSyncTestDB(t)
	cfg.Paths.HomeBaseDir = base
	u := models.User{Username: "fixture", Enabled: false}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	entry := models.KnownHostsEntry{UserID: u.ID, Entry: "example.test ssh-ed25519 AAAA"}
	if err := db.Create(&entry).Error; err != nil {
		t.Fatal(err)
	}
	s := New(db, osadapter.NewLinuxAdapter(), *slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.lookupUser = func(string) (*osuser.User, error) { return &osuser.User{Uid: "1001", Gid: "1001"}, nil }
	if err := s.IngressKeyFromDB(u); err != nil {
		t.Fatal(err)
	}
	if err := s.KnownHostsFromDB(&u); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"authorized_keys", "known_hosts"} {
		path := filepath.Join(home, ".ssh", name)
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			t.Fatal(err)
		}
		if st.Uid != 1001 || st.Gid != 1001 || st.Mode&0777 != 0600 {
			t.Fatalf("unsafe file metadata: %+v", st)
		}
	}
	if err := os.RemoveAll(filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(victim, "authorized_keys")
	if err := os.WriteFile(target, []byte("victim"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	if err := s.IngressKeyFromDB(u); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := s.KnownHostsFromDB(&u); err == nil {
		t.Fatal("known hosts symlink accepted")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "victim" {
		t.Fatalf("victim changed: %q, %v", got, err)
	}
}
