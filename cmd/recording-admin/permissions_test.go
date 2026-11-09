package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"goBastion/internal/recording/permissions"
	"golang.org/x/sys/unix"
)

func TestPermissionsCLIRequiresOffline(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if code := executePermissions([]string{"apply", "--archive", "/run/archive", "--user", "victim", "--backup", "/run/backup"}, &out, &diagnostics); code != 2 {
		t.Fatalf("apply without offline assertion: code=%d", code)
	}
}

func rootPermissionFixture(t *testing.T, name ...string) (archive, backup, account, server, recording string) {
	t.Helper()
	if os.Getenv("GOB_TEST_ROOT_SSH_SPOOL") != "1" {
		t.Skip("requires disposable root test container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	shared, err := user.LookupGroup("gobastion")
	if err != nil {
		t.Fatal(err)
	}
	sharedID, err := strconv.Atoi(shared.Gid)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("/run", "recording-permissions-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	archive = filepath.Join(base, "archive")
	backup = filepath.Join(base, "metadata.json")
	username := "victim"
	if len(name) != 0 {
		username = name[0]
	}
	account = filepath.Join(archive, username)
	server = filepath.Join(account, "server")
	recording = filepath.Join(server, "session.ttyrec.gz")
	for _, path := range []string{archive, account, server} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, sharedID); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, os.ModeSetgid|os.ModeSticky|0770); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(recording, []byte("recording payload"), 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(recording, 0, sharedID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(recording, 0660); err != nil {
		t.Fatal(err)
	}
	return
}

func mustModeOwner(t *testing.T, path string, uid, gid uint32, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	gotMode := info.Mode().Perm()
	if info.Mode()&os.ModeSetgid != 0 {
		gotMode |= os.ModeSetgid
	}
	if info.Mode()&os.ModeSticky != 0 {
		gotMode |= os.ModeSticky
	}
	if st.Uid != uid || st.Gid != gid || gotMode != mode {
		t.Fatalf("%s: uid=%d gid=%d mode=%#o, want uid=%d gid=%d mode=%#o", path, st.Uid, st.Gid, gotMode, uid, gid, mode)
	}
}

func TestRootRecordingPermissionsMigration(t *testing.T) {
	archive, backup, account, server, file := rootPermissionFixture(t)
	spool := filepath.Join(server, ".ssh-record-test")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(spool, 0700); err != nil {
		t.Fatal(err)
	}
	spoolFile := filepath.Join(spool, "capture.ttyrec")
	if err := os.WriteFile(spoolFile, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	shared, _ := user.LookupGroup("gobastion")
	sharedID, _ := strconv.Atoi(shared.Gid)
	if err := os.Chown(spoolFile, 0, sharedID); err != nil {
		t.Fatal(err)
	}
	auditors, _ := user.LookupGroup("gobastion-auditors")
	auditorsID, _ := strconv.Atoi(auditors.Gid)
	if _, err := permissions.Plan(archive, "victim"); err != nil {
		t.Fatal(err)
	}
	if err := permissions.Apply(archive, "victim", backup); err != nil {
		t.Fatal(err)
	}
	mustModeOwner(t, archive, 0, uint32(sharedID), 0751)
	for _, dir := range []string{account, server} {
		mustModeOwner(t, dir, 1000, uint32(auditorsID), os.ModeSetgid|0750)
	}
	mustModeOwner(t, file, 1000, uint32(auditorsID), 0640)
	mustModeOwner(t, spool, 0, uint32(sharedID), 0700)
	mustModeOwner(t, spoolFile, 0, uint32(sharedID), 0600)
	if data, err := os.ReadFile(file); err != nil || string(data) != "recording payload" {
		t.Fatalf("recording payload changed: %v", err)
	}
	backupInfo, err := os.Lstat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if backupInfo.Mode().Perm() != 0600 || backupInfo.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("backup metadata is not protected")
	}
	// A crash after chown can clear setgid. Reapply from the same backup.
	if err := os.Chmod(server, 0750); err != nil {
		t.Fatal(err)
	}
	if err := permissions.Apply(archive, "victim", backup); err != nil {
		t.Fatal(err)
	}
	mustModeOwner(t, server, 1000, uint32(auditorsID), os.ModeSetgid|0750)
	if err := permissions.Rollback(archive, "victim", backup); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{archive, account, server} {
		mustModeOwner(t, dir, 0, uint32(sharedID), os.ModeSetgid|os.ModeSticky|0770)
	}
	mustModeOwner(t, file, 0, uint32(sharedID), 0660)
	mustModeOwner(t, spool, 0, uint32(sharedID), 0700)
	mustModeOwner(t, spoolFile, 0, uint32(sharedID), 0600)
	if err := permissions.Rollback(archive, "victim", backup); err != nil {
		t.Fatal(err)
	}
}

func TestRootRecordingPermissionsRejectsUnsafeInodes(t *testing.T) {
	for _, setup := range []struct {
		name   string
		change func(string, string, string) error
	}{
		{"symlink", func(_, _, file string) error {
			if err := os.Remove(file); err != nil {
				return err
			}
			return os.Symlink("/etc/passwd", file)
		}},
		{"hardlink", func(_, _, file string) error { return os.Link(file, file+".ttyrec") }},
		{"foreign owner", func(_, _, file string) error { return os.Chown(file, 1002, 1001) }},
		{"spool symlink", func(_, _, file string) error {
			spool := filepath.Join(filepath.Dir(file), ".ssh-record-test")
			if err := os.Mkdir(spool, 0700); err != nil {
				return err
			}
			if err := os.Chmod(spool, 0700); err != nil {
				return err
			}
			return os.Symlink("/etc/passwd", filepath.Join(spool, "capture.ttyrec"))
		}},
	} {
		t.Run(setup.name, func(t *testing.T) {
			archive, backup, account, _, file := rootPermissionFixture(t)
			if err := setup.change(archive, account, file); err != nil {
				t.Fatal(err)
			}
			if err := permissions.Apply(archive, "victim", backup); err == nil {
				t.Fatal("unsafe inode accepted")
			}
			if _, err := os.Lstat(backup); !os.IsNotExist(err) {
				t.Fatal("backup created for rejected inventory")
			}
		})
	}
}

func TestRootRecordingPermissionsRejectsChangedIdentity(t *testing.T) {
	archive, backup, _, _, file := rootPermissionFixture(t)
	if err := permissions.Apply(archive, "victim", backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := permissions.Rollback(archive, "victim", backup); err == nil {
		t.Fatal("changed inode accepted")
	}
}

func TestRootRecordingPermissionsIgnoresInterruptedTemporaryBackup(t *testing.T) {
	archive, backup, _, _, _ := rootPermissionFixture(t)
	stale := filepath.Join(filepath.Dir(backup), ".recording-permissions-interrupted")
	if err := os.WriteFile(stale, []byte("{incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := permissions.Apply(archive, "victim", backup); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatal(err)
	}
	if err := permissions.Apply(archive, "victim", backup); err != nil {
		t.Fatal(err)
	}
}

func TestRootRecordingPermissionsRejectsOtherManagedProcess(t *testing.T) {
	archive, backup, _, _, _ := rootPermissionFixture(t)
	cmd := exec.Command("/bin/sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1002, Gid: 1001}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if err := permissions.Apply(archive, "victim", backup); err == nil {
		t.Fatal("other managed UID process accepted")
	}
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Fatal("backup created while managed process was active")
	}
}

func TestRootRecordingPermissionsSerializesMigration(t *testing.T) {
	archive, backup, _, _, _ := rootPermissionFixture(t)
	fd, err := unix.Open(archive, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	if err := permissions.Apply(archive, "victim", backup); err == nil {
		t.Fatal("migration ran while archive lock held")
	}
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Fatal("backup created while archive lock held")
	}
}

func setNamedACL(t *testing.T, path, attr string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	raw := make([]byte, 4)
	binary.LittleEndian.PutUint32(raw, 2)
	for _, item := range []struct {
		tag, perm uint16
		id        uint32
	}{
		{1, 7, ^uint32(0)}, {2, 4, 1002}, {4, 4, ^uint32(0)}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)},
	} {
		field := make([]byte, 8)
		binary.LittleEndian.PutUint16(field, item.tag)
		binary.LittleEndian.PutUint16(field[2:], item.perm)
		binary.LittleEndian.PutUint32(field[4:], item.id)
		raw = append(raw, field...)
	}
	if err := unix.Fsetxattr(int(f.Fd()), attr, raw, 0); err == unix.ENOTSUP {
		t.Skip("filesystem does not support POSIX ACL")
	} else if err != nil {
		t.Fatal(err)
	}
}

func TestRootRecordingPermissionsRejectsACL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected func(string, string, string) string
		attr     string
	}{
		{"archive ancestor", func(archive, _, _ string) string { return filepath.Dir(archive) }, "system.posix_acl_access"},
		{"server default", func(_, server, _ string) string { return server }, "system.posix_acl_default"},
		{"recording access", func(_, _, file string) string { return file }, "system.posix_acl_access"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive, backup, _, server, file := rootPermissionFixture(t)
			setNamedACL(t, tc.selected(archive, server, file), tc.attr)
			if _, err := permissions.Plan(archive, "victim"); err == nil {
				t.Fatal("ACL accepted by dry run")
			}
			if err := permissions.Apply(archive, "victim", backup); err == nil {
				t.Fatal("ACL accepted by apply")
			}
			if _, err := os.Lstat(backup); !os.IsNotExist(err) {
				t.Fatal("backup created for rejected ACL")
			}
		})
	}
}

func TestRootRetiredRecordingPermissionsMigration(t *testing.T) {
	archive, backup, account, server, file := rootPermissionFixture(t, "retiredone")
	shared, _ := user.LookupGroup("gobastion")
	auditors, _ := user.LookupGroup("gobastion-auditors")
	sharedID, _ := strconv.Atoi(shared.Gid)
	auditorsID, _ := strconv.Atoi(auditors.Gid)
	// A prior owner may survive on files after account deletion, while its
	// namespace directories have already been restored to root ownership.
	if err := os.Chown(file, 1008, sharedID); err != nil {
		t.Fatal(err)
	}
	p, err := permissions.Plan(archive, "retiredone", true)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Retired || p.Entries[len(p.Entries)-1].DesiredUID != 0 {
		t.Fatal("retired plan must be root-owned")
	}
	if err := permissions.Apply(archive, "retiredone", backup, true); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{account, server} {
		mustModeOwner(t, dir, 0, uint32(auditorsID), os.ModeSetgid|0750)
	}
	mustModeOwner(t, file, 0, uint32(auditorsID), 0640)
	if err := permissions.Rollback(archive, "retiredone", backup, true); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{archive, account, server} {
		mustModeOwner(t, dir, 0, uint32(sharedID), os.ModeSetgid|os.ModeSticky|0770)
	}
	mustModeOwner(t, file, 1008, uint32(sharedID), 0660)
}

func TestRootRetiredRecordingRejectsMixedPriorOwners(t *testing.T) {
	archive, backup, _, server, file := rootPermissionFixture(t, "retiredone")
	if err := os.Chown(file, 1008, 1001); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(server, "second.ttyrec.gz")
	if err := os.WriteFile(second, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(second, 1009, 1001); err != nil {
		t.Fatal(err)
	}
	if err := permissions.Apply(archive, "retiredone", backup, true); err == nil {
		t.Fatal("mixed prior owners accepted")
	}
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Fatal("backup created for rejected inventory")
	}
}

func TestRootRetiredRecordingRejectsPendingSpool(t *testing.T) {
	archive, backup, _, server, _ := rootPermissionFixture(t, "retiredone")
	spool := filepath.Join(server, ".ssh-record-pending")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(spool, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, "capture.ttyrec"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := permissions.Apply(archive, "retiredone", backup, true); err == nil {
		t.Fatal("retired pending spool accepted")
	}
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Fatal("backup created for pending retired spool")
	}
}
