package recording

import (
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestRootRecordingExposureAudit verifies raw file access and account reservation
// isolation. Run only inside a disposable root
// container with GOB_TEST_RECORDING_EXPOSURE_AUDIT=1. UID 1000 is the victim,
// UID 1002 is another bastion account, and GID 1001 is their shared group.
func TestRootRecordingExposureAudit(t *testing.T) {
	if os.Getenv("GOB_TEST_RECORDING_EXPOSURE_AUDIT") != "1" {
		t.Skip("requires explicit disposable-root recording exposure audit")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root in a disposable container")
	}
	oldUmask := syscall.Umask(0007)
	defer syscall.Umask(oldUmask)
	base, err := os.MkdirTemp("/run", "gobastion-recording-exposure-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}

	newArchive := func(name string) string {
		t.Helper()
		archive := filepath.Join(base, name)
		if err := os.Mkdir(archive, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(archive, 0, 1001); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(archive, 0751); err != nil {
			t.Fatal(err)
		}
		return archive
	}

	t.Run("CrossUserRead", func(t *testing.T) {
		archive := newArchive("published")
		if err := ProvisionAccount(archive, "victim"); err != nil {
			t.Fatal(err)
		}
		runRecordingExposureHelper(t, 1000, "publish", archive)
		path := filepath.Join(archive, "victim", "server", "session.ttyrec.gz")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("victim recording was not published: %v", err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != 1000 || stat.Gid != uint32(mustAuditorGID(t)) || info.Mode().Perm() != 0640 {
			t.Fatalf("incorrect recording identity/mode: %+v %v", stat, info.Mode())
		}
		for _, dir := range []string{filepath.Dir(path), filepath.Dir(filepath.Dir(path))} {
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&(os.ModePerm|os.ModeSetgid) != os.ModeSetgid|0750 {
				t.Fatalf("SGID inheritance lost: %s %v", dir, info.Mode())
			}
		}
		if got := runRecordingExposureHelper(t, 1004, "read", path); got != "ACCESS_GRANTED" {
			t.Fatalf("auditor cannot read recording: %s", got)
		}
		result := runRecordingExposureHelper(t, 1002, "read", path)
		if result != "ACCESS_DENIED" {
			t.Fatalf("another bastion UID read the victim recording: %s", result)
		}
	})

	t.Run("AccountPreemption", func(t *testing.T) {
		archive := newArchive("preemption")
		result := runRecordingExposureHelper(t, 1002, "precreate", filepath.Join(archive, "future"))
		if result != "CREATE_DENIED" {
			t.Errorf("another bastion UID reserved the victim account path: %s", result)
		}
		// Root reserves the path only after the unprivileged precreation attempt.
		if err := ProvisionAccount(archive, "future"); err != nil {
			t.Fatal(err)
		}
		runRecordingExposureHelper(t, 1003, "spool", archive)
	})
}

func runRecordingExposureHelper(t *testing.T, uid uint32, action, path string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestRecordingExposureAuditHelper$")
	cmd.Env = []string{
		"GOB_TEST_RECORDING_EXPOSURE_AUDIT=1",
		"GOB_RECORDING_EXPOSURE_HELPER=" + action,
		"GOB_RECORDING_EXPOSURE_PATH=" + path,
	}
	groups := []uint32{1001}
	if uid == 1004 {
		groups = append(groups, uint32(mustAuditorGID(t)))
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: 1001, Groups: groups}}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s as UID %d failed: %v: %s", action, uid, err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "ACCESS_") || strings.HasPrefix(line, "CREATE_") {
			return line
		}
	}
	return strings.TrimSpace(string(output))
}

// TestRecordingExposureAuditHelper is a subprocess entry point. Its marker is
// private to the opt-in audit and it performs no work in ordinary test runs.
func TestRecordingExposureAuditHelper(t *testing.T) {
	action := os.Getenv("GOB_RECORDING_EXPOSURE_HELPER")
	if os.Getenv("GOB_TEST_RECORDING_EXPOSURE_AUDIT") != "1" || action == "" {
		t.Skip("subprocess helper")
	}
	path := os.Getenv("GOB_RECORDING_EXPOSURE_PATH")
	switch action {
	case "publish":
		spool, err := NewSSHSpool(path, "victim/server")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = spool.Close(true) }()
		raw := filepath.Join(spool.WorkPath, "session.ttyrec")
		if err := os.WriteFile(raw, []byte("victim recording"), 0600); err != nil {
			t.Fatal(err)
		}
		compressed := filepath.Join(spool.WorkPath, "session.gz")
		out, err := os.Create(compressed)
		if err != nil {
			t.Fatal(err)
		}
		writer := gzip.NewWriter(out)
		if _, err := writer.Write([]byte("victim recording")); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
		if err := Publish(path, compressed, "victim/server/session.ttyrec.gz", os.Geteuid()); err != nil {
			t.Fatal(err)
		}
	case "read":
		_, err := os.ReadFile(path)
		if err == nil {
			fmt.Println("ACCESS_GRANTED")
		} else if os.IsPermission(err) {
			fmt.Println("ACCESS_DENIED")
		} else {
			t.Fatal(err)
		}
	case "precreate":
		err := os.Mkdir(path, 0700)
		if err == nil {
			fmt.Println("CREATE_GRANTED")
		} else if os.IsPermission(err) {
			fmt.Println("CREATE_DENIED")
		} else {
			t.Fatal(err)
		}
	case "spool":
		spool, err := NewSSHSpool(path, "future/server")
		if err != nil {
			t.Fatal(err)
		}
		if err := spool.Close(true); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown audit helper action %q", action)
	}
}
