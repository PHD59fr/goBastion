package recording

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

// Run only in the disposable root container prepared by test-secret-root.sh.
func TestRootRecordingAccountPublicationAndDBRecovery(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_SPOOL") != "1" {
		t.Skip("requires disposable root environment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	account, err := user.Lookup("recording-test")
	if err != nil || account.Uid != "1001" || account.Gid != "1001" {
		t.Fatalf("disposable recording account unavailable: account=%+v err=%v", account, err)
	}
	base, err := os.MkdirTemp("/run", "gobastion-account-recording-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
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
	if err := os.Chmod(archive, 0751); err != nil {
		t.Fatal(err)
	}
	if err := ProvisionAccount(archive, "recording-test"); err != nil {
		t.Fatal(err)
	}
	accountDir := filepath.Join(archive, "recording-test")
	serverDir := filepath.Join(accountDir, "server")
	source := filepath.Join(base, "source.gz")
	const payload = "root DB publication"
	if err := os.WriteFile(source, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(serverDir, "session.gz")
	if err := PublishAccount(archive, source, "recording-test/server/session.gz"); err != nil {
		t.Fatal(err)
	}
	checkAccountRecording(t, published, payload)
	for _, path := range []string{accountDir, serverDir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&(os.ModePerm|os.ModeSetgid) != os.ModeSetgid|0750 {
			t.Fatalf("publication widened private directory %s: %v", path, info.Mode())
		}
	}
	for _, name := range []string{"missing-recording-user", "nobody", "root"} {
		if err := PublishAccount(archive, source, name+"/server/rejected.gz"); err == nil {
			t.Fatalf("unacceptable recording account %q accepted", name)
		}
	}
	for _, relative := range []string{
		"recording-test/server",
		"recording-test/server/extra/rejected.gz",
		"recording-test/./rejected.gz",
		"recording-test/server/../rejected.gz",
		"RECORDING-TEST/server/rejected.gz",
	} {
		if err := PublishAccount(archive, source, relative); err == nil {
			t.Fatalf("malformed recording account path %q accepted", relative)
		}
	}

	pending := filepath.Join(archive, ".db-pending")
	if err := os.Mkdir(pending, 0700); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(pending, "db-record-account-test")
	if err := os.Mkdir(spool, 0700); err != nil {
		t.Fatal(err)
	}
	const rawName = "recovered.ttyrec"
	lock, err := Prepare(spool, "recording-test/server/"+rawName+".gz", rawName)
	if err != nil {
		t.Fatal(err)
	}
	const recovered = "root DB recovered session"
	if err := os.WriteFile(filepath.Join(spool, rawName), []byte(recovered), 0600); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	Recover(archive, slog.New(slog.NewTextHandler(io.Discard, nil)))
	checkAccountRecording(t, filepath.Join(serverDir, rawName+".gz"), "")
	if got := readGzip(t, filepath.Join(serverDir, rawName+".gz")); got != recovered {
		t.Fatalf("recovered recording = %q, want %q", got, recovered)
	}
	if _, err := os.Lstat(spool); !os.IsNotExist(err) {
		t.Fatalf("recovered DB spool still present: %v", err)
	}
}

func checkAccountRecording(t *testing.T, path, want string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 1001 || stat.Gid != uint32(mustAuditorGID(t)) || info.Mode().Perm() != 0640 {
		t.Fatalf("recording %s has owner/mode %+v %v", path, stat, info.Mode())
	}
	cmd := exec.Command("/bin/cat", path)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1001, Gid: 1001}}
	data, err := cmd.Output()
	if err != nil {
		t.Fatalf("recording cannot be read by account UID: %v", err)
	}
	if want != "" && string(data) != want {
		t.Fatalf("recording = %q, want %q", data, want)
	}
}

func mustAuditorGID(t *testing.T) int {
	t.Helper()
	gid, err := recordingGroupID(AuditorGroup)
	if err != nil {
		t.Fatal(err)
	}
	return gid
}

func TestProvisionAccountRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("nonroot assertion")
	}
	if err := ProvisionAccount(privateTestArchive(t), "root"); err == nil {
		t.Fatal("unprivileged account provisioning accepted")
	}
}

// This test runs only in the disposable root environment, never host homes.
func TestRootRecordingAccountProvisioning(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_SPOOL") != "1" {
		t.Skip("requires disposable root environment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	base, err := os.MkdirTemp("/run", "gobastion-provision-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	shared, err := recordingGroupID("gobastion")
	if err != nil {
		t.Fatal(err)
	}
	newArchive := func(name string) string {
		t.Helper()
		path := filepath.Join(base, name)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, shared); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0751); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Run("ConcurrentIdempotence", func(t *testing.T) {
		archive := newArchive("concurrent")
		errs := make(chan error, 12)
		var workers sync.WaitGroup
		for range 12 {
			workers.Go(func() { errs <- ProvisionAccount(archive, "recording-test") })
		}
		workers.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		info, err := os.Stat(filepath.Join(archive, "recording-test"))
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		if st.Uid != 1001 || st.Gid != uint32(mustAuditorGID(t)) || info.Mode()&(os.ModePerm|os.ModeSetgid) != os.ModeSetgid|0750 {
			t.Fatalf("incorrect provisioned identity/mode: %+v %v", st, info.Mode())
		}
		entries, err := os.ReadDir(archive)
		if err != nil || len(entries) != 1 {
			t.Fatalf("staging entries leaked: %v %v", entries, err)
		}
	})
	for _, variant := range []string{"foreign-owner", "foreign-group", "legacy-mode", "symlink"} {
		t.Run(variant, func(t *testing.T) {
			archive := newArchive(variant)
			account := filepath.Join(archive, "recording-test")
			if variant == "symlink" {
				target := filepath.Join(base, "symlink-target")
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, account); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(account, 0700); err != nil {
					t.Fatal(err)
				}
				uid, gid := 1001, mustAuditorGID(t)
				if variant == "foreign-owner" {
					uid = 1002
				}
				if variant == "foreign-group" {
					gid = shared
				}
				if err := os.Chown(account, uid, gid); err != nil {
					t.Fatal(err)
				}
				mode := os.ModeSetgid | os.FileMode(0750)
				if variant == "legacy-mode" {
					mode = os.ModeSetgid | os.ModeSticky | 0770
				}
				if err := os.Chmod(account, mode); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(account)
			if err != nil {
				t.Fatal(err)
			}
			if err := ProvisionAccount(archive, "recording-test"); err == nil {
				t.Fatal("unsafe existing account accepted")
			}
			after, err := os.Lstat(account)
			if err != nil {
				t.Fatal(err)
			}
			b, a := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
			if before.Mode() != after.Mode() || b.Uid != a.Uid || b.Gid != a.Gid || b.Ino != a.Ino {
				t.Fatal("unsafe account was modified")
			}
		})
	}
}
