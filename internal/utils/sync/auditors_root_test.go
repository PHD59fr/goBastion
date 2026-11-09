package sync

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/recording"
)

func TestRootRecordingAuditorRevocation(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_PUBLISH") != "1" {
		t.Skip("requires disposable root container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root in a dedicated container")
	}
	account, err := osuser.Lookup("administrator")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid != 1004 {
		t.Fatal("unexpected isolated fixture identity")
	}
	auditGroup, err := osuser.LookupGroup(recording.AuditorGroup)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("/run", "gobastion-auditor-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err = os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(base, "archive")
	if err = os.Mkdir(archive, 0751); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(archive, 0, 1001); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(archive, 0751); err != nil {
		t.Fatal(err)
	}
	if err = recording.ProvisionAccount(archive, "victim"); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "source")
	if err = os.WriteFile(source, []byte("private recording"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = recording.PublishAccount(archive, source, "victim/server/session.ttyrec.gz"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(archive, "victim/server/session.ttyrec.gz")
	// Membership changes belong to this disposable fixture, never host accounts.
	if out, e := exec.Command("/usr/sbin/addgroup", "administrator", recording.AuditorGroup).CombinedOutput(); e != nil {
		t.Fatalf("restore fixture group: %v %s", e, out)
	}
	t.Cleanup(func() {
		if out, e := exec.Command("/usr/sbin/addgroup", "administrator", recording.AuditorGroup).CombinedOutput(); e != nil {
			t.Errorf("restore fixture group: %v %s", e, out)
		}
	})
	start := func(mode string) *exec.Cmd {
		t.Helper()
		fresh, e := osuser.Lookup("administrator")
		if e != nil {
			t.Fatal(e)
		}
		gids, e := fresh.GroupIds()
		if e != nil {
			t.Fatal(e)
		}
		groups := make([]uint32, 0, len(gids))
		for _, raw := range gids {
			n, e := strconv.ParseUint(raw, 10, 32)
			if e != nil {
				t.Fatal(e)
			}
			groups = append(groups, uint32(n))
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestRootAuditorProcessHelper$")
		cmd.Env = []string{"GOB_AUDITOR_PROCESS_HELPER=" + mode, "GOB_AUDITOR_PROCESS_PATH=" + path}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: 1001, Groups: groups}}
		cmd.Stderr = os.Stderr
		return cmd
	}
	cmd := start("hold")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		if !waited {
			_ = cmd.Wait()
		}
		_ = pipe.Close()
	})
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(pipe).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "READY\n" {
			t.Fatalf("authorized reader did not open recording: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not become ready")
	}
	db, _ := newSyncTestDB(t)
	if err = db.Create(&models.User{Username: "administrator", Role: models.RoleUser, Enabled: true}).Error; err != nil {
		t.Fatal(err)
	}
	s := New(db, osadapter.NewLinuxAdapter(), *slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err = s.reconcileAuditors(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("old reader credentials survived: %v", err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("expected revoked process to be killed: %v", err)
	}
	fresh, err := osuser.Lookup("administrator")
	if err != nil {
		t.Fatal(err)
	}
	groups, err := fresh.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g == auditGroup.Gid {
			t.Fatal("demoted actor remains an auditor")
		}
	}
	denied := start("denied")
	denied.Stderr = nil
	if out, e := denied.CombinedOutput(); e != nil {
		t.Fatalf("new unprivileged reader: %v %s", e, out)
	}
}

func TestRootAuditorProcessHelper(t *testing.T) {
	mode := os.Getenv("GOB_AUDITOR_PROCESS_HELPER")
	if mode == "" {
		t.Skip("isolated credential helper")
	}
	_, err := os.ReadFile(os.Getenv("GOB_AUDITOR_PROCESS_PATH"))
	if mode == "denied" {
		if !os.IsPermission(err) {
			t.Fatalf("expected denied read: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("READY")
	for {
		time.Sleep(time.Hour)
	}
}
