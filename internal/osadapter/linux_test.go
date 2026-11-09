package osadapter

import (
	"os"
	"path/filepath"
	"testing"

	"goBastion/internal/models"
)

func TestLinuxAdapterReservedManagedNames(t *testing.T) {
	adapter := &LinuxAdapter{}
	for _, name := range []string{"gobastion", "nobody", "gobastion-session"} {
		if err := adapter.CreateUser(name); err == nil {
			t.Fatalf("created reserved account %q", name)
		}
		if err := adapter.DeleteUser(name); err == nil {
			t.Fatalf("deleted reserved account %q", name)
		}
		if err := adapter.UpdateSudoers(&models.User{Username: name}); err == nil {
			t.Fatalf("updated protected sudoers %q", name)
		}
	}
}

func TestLinuxAdapterChownDirRejectsOtherPaths(t *testing.T) {
	adapter := &LinuxAdapter{}
	if err := adapter.ChownDir(models.User{Username: "alice"}, "/tmp/alice/.ssh"); err == nil {
		t.Fatal("arbitrary chown target accepted")
	}
}

func TestRootLegacySudoersRemoval(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_SPOOL") != "1" {
		t.Skip("requires disposable root container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	dir := "/etc/sudoers.d"
	ensureRootSudoersFixture(t, dir)
	name := "gobastion-legacy-test"
	path := filepath.Join(dir, name)
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("fixture sudoers entry already exists")
	}
	if err := os.WriteFile(path, []byte(`gobastion-legacy-test ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-adduser *
gobastion-legacy-test ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-passwd-delete *
gobastion-legacy-test ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-deluser *
gobastion-legacy-test ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-chown-ssh *
gobastion-legacy-test ALL=(root) NOPASSWD: /usr/local/sbin/gobastion-sudoers *
`), 0440); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	if err := (&LinuxAdapter{}).UpdateSudoers(&models.User{Username: name, Role: models.RoleAdmin, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("legacy sudoers entry survived")
	}
	protected := filepath.Join(dir, "gobastion-session")
	if _, err := os.Lstat(protected); os.IsNotExist(err) {
		if err := os.WriteFile(protected, []byte("global policy\n"), 0440); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(protected) })
	}
	before, err := os.ReadFile(protected)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&LinuxAdapter{}).UpdateSudoers(&models.User{Username: "gobastion-session"}); err == nil {
		t.Fatal("global sudoers policy accepted for deletion")
	}
	after, err := os.ReadFile(protected)
	if err != nil || string(after) != string(before) {
		t.Fatal("global sudoers policy changed")
	}
}

func TestRootLegacySudoersRejectsSymlink(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_SPOOL") != "1" {
		t.Skip("requires disposable root container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	name := "gobastion-legacy-link"
	ensureRootSudoersFixture(t, "/etc/sudoers.d")
	path := filepath.Join("/etc/sudoers.d", name)
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("fixture sudoers entry already exists")
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	if err := (&LinuxAdapter{}).UpdateSudoers(&models.User{Username: name}); err == nil {
		t.Fatal("symlink sudoers entry accepted")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink unexpectedly changed")
	}
}

func ensureRootSudoersFixture(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(dir) })
	} else if err != nil {
		t.Fatal(err)
	}
}

func TestRootLegacySudoersRejectsUnrelatedPolicy(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_SPOOL") != "1" {
		t.Skip("requires disposable root container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	ensureRootSudoersFixture(t, "/etc/sudoers.d")
	name := "gobastion-policy-other"
	path := filepath.Join("/etc/sudoers.d", name)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("fixture path is not absent:", err)
	}
	const policy = "operator ALL=(root) NOPASSWD: /usr/bin/true\n"
	if err := os.WriteFile(path, []byte(policy), 0440); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	if err := (&LinuxAdapter{}).UpdateSudoers(&models.User{Username: name, Role: models.RoleAdmin, Enabled: true}); err == nil {
		t.Fatal("unrelated root policy accepted for deletion")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != policy {
		t.Fatal("unrelated policy was modified")
	}
}

func TestManagedNameNeverMapsForeignOrMalformedIdentities(t *testing.T) {
	for _, name := range []string{"realm/alice", "../alice", "ALICE", " alice"} {
		if _, err := managedName(name); err == nil {
			t.Fatalf("noncanonical identity %q accepted", name)
		}
	}
	if got, err := managedName("alice..ops"); err != nil || got != "alice..ops" {
		t.Fatalf("local identity silently rewritten: %q %v", got, err)
	}
}
