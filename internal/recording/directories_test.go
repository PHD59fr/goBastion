package recording

import (
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func privateTestArchive(t *testing.T) string {
	t.Helper()
	archive := t.TempDir()
	if err := os.Chmod(archive, 0700); err != nil {
		t.Fatal(err)
	}
	return archive
}

func TestOpenArchiveDirectoryRejectsSymlinkComponents(t *testing.T) {
	for _, position := range []string{"first", "middle", "archive", "account", "server"} {
		t.Run(position, func(t *testing.T) {
			base := t.TempDir()
			real := filepath.Join(base, "real")
			if err := os.MkdirAll(filepath.Join(real, "middle", "archive", "account", "server"), 0700); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(real, "middle", "archive")
			relative := "account/server"
			switch position {
			case "first":
				if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
					t.Fatal(err)
				}
				archive = filepath.Join(base, "link", "middle", "archive")
			case "middle":
				if err := os.Symlink(filepath.Join(real, "middle"), filepath.Join(real, "link")); err != nil {
					t.Fatal(err)
				}
				archive = filepath.Join(real, "link", "archive")
			case "archive":
				if err := os.Symlink(archive, filepath.Join(real, "middle", "link")); err != nil {
					t.Fatal(err)
				}
				archive = filepath.Join(real, "middle", "link")
			case "account":
				if err := os.Symlink("account", filepath.Join(archive, "link")); err != nil {
					t.Fatal(err)
				}
				relative = "link/server"
			case "server":
				if err := os.Symlink("server", filepath.Join(archive, "account", "link")); err != nil {
					t.Fatal(err)
				}
				relative = "account/link"
			}
			if dir, err := openArchiveDirectory(archive, relative, os.Geteuid()); err == nil {
				_ = dir.Close()
				t.Fatal("symlink component accepted")
			}
		})
	}
}

func TestOpenArchiveDirectoryPreservesPrivateDirectories(t *testing.T) {
	archive := privateTestArchive(t)
	server := filepath.Join(archive, "account", "server")
	if err := os.MkdirAll(server, 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{archive, filepath.Join(archive, "account"), server} {
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := openArchiveDirectory(archive, "account/server", os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{archive, filepath.Join(archive, "account"), server} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModePerm != 0700 || info.Mode()&os.ModeSticky != 0 {
			t.Fatalf("%s mode changed to %v", path, info.Mode())
		}
	}
}

func TestOpenArchiveDirectoryRejectsWorldWritableDirectories(t *testing.T) {
	for _, position := range []string{"archive", "account", "server"} {
		t.Run(position, func(t *testing.T) {
			archive := privateTestArchive(t)
			account := filepath.Join(archive, "account")
			server := filepath.Join(account, "server")
			if err := os.MkdirAll(server, 0700); err != nil {
				t.Fatal(err)
			}
			path := map[string]string{"archive": archive, "account": account, "server": server}[position]
			if err := os.Chmod(path, 0777); err != nil {
				t.Fatal(err)
			}
			if dir, err := openArchiveDirectory(archive, "account/server", os.Geteuid()); err == nil {
				_ = dir.Close()
				t.Fatal("world-writable directory accepted")
			}
		})
	}
}

func TestOpenArchiveDirectoryRejectsWritableAncestor(t *testing.T) {
	base := t.TempDir()
	ancestor := filepath.Join(base, "shared")
	archive := filepath.Join(ancestor, "archive")
	if err := os.MkdirAll(archive, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0770); err != nil {
		t.Fatal(err)
	}
	if dir, err := openArchiveDirectory(archive, ".", os.Geteuid()); err == nil {
		_ = dir.Close()
		t.Fatal("non-sticky writable ancestor accepted")
	}
}

func TestSSHSpoolNormalizesInheritedSetgidAndRemovesEmptyDirectory(t *testing.T) {
	archive := privateTestArchive(t)
	parent := filepath.Join(archive, "account", "server")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSetgid|0770); err != nil {
		t.Fatal(err)
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if parentInfo.Mode()&os.ModeSetgid == 0 {
		t.Fatal("test parent lacks setgid")
	}
	parentFD, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := newSSHSpoolAt(parentFD, parent)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(spool.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSticky) != 0700 {
		t.Fatalf("spool mode = %v, want 0700", info.Mode())
	}
	if err := spool.Close(true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(spool.Path); !os.IsNotExist(err) {
		t.Fatalf("empty spool still present: %v", err)
	}
	info, err = os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSticky != 0 {
		t.Fatal("raw spool creation modified parent permissions")
	}
}

func TestPublishRejectsLegacySharedParent(t *testing.T) {
	archive := privateTestArchive(t)
	parent := filepath.Join(archive, "account", "server")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSetgid|os.ModeSticky|0770); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "recording.gz")
	if err := os.WriteFile(source, []byte("recorded"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Publish(archive, source, "account/server/session.ttyrec.gz", os.Geteuid()); err == nil {
		t.Fatal("legacy shared parent accepted")
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSticky == 0 || info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("publication changed parent mode: %v", info.Mode())
	}
}

func TestRecoverArchiveRootPublicationStage(t *testing.T) {
	archive := privateTestArchive(t)
	stage := filepath.Join(archive, ".publish-abandoned")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, ".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "recording.gz"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	Recover(archive, slog.Default())
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("abandoned publication stage still present: %v", err)
	}
}

// This test only runs in scripts/test-secret-root.sh's disposable container.
func TestRootRecordingStickyDirectories(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_SPOOL") != "1" {
		t.Skip("requires disposable root environment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	base, err := os.MkdirTemp("/run", "gobastion-legacy-recording-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	archive := filepath.Join(base, "archive")
	if err := os.Mkdir(archive, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(archive, 0, 1001); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(archive, os.ModeSetgid|os.ModeSticky|0770); err != nil {
		t.Fatal(err)
	}
	if dir, err := openArchiveDirectory(archive, ".", 1001); err == nil {
		_ = dir.Close()
		t.Fatal("legacy shared archive accepted")
	}
	if err := ProvisionAccount(archive, "recording-test"); err == nil {
		t.Fatal("provisioning repaired legacy shared archive")
	}
	info, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSticky) != os.ModeSetgid|os.ModeSticky|0770 {
		t.Fatal("legacy archive modified")
	}
}

func TestRecoverNestedPublicationStage(t *testing.T) {
	archive := privateTestArchive(t)
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(archive, account.Username, "server", ".publish-abandoned")
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, ".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "recording.gz"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	Recover(archive, slog.Default())
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("nested publication stage still present: %v", err)
	}
}
