package sync

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/recording"
)

type auditorAdapter struct {
	*osadapter.MockAdapter
	members   map[string]bool
	failKill  bool
	calls     []string
	noProcess error
}

func (a *auditorAdapter) ExecCommand(name string, args ...string) (string, error) {
	a.calls = append(a.calls, strings.Join(append([]string{name}, args...), " "))
	switch name {
	case "/usr/bin/getent":
		if len(args) == 2 && args[0] == "group" {
			if args[1] == "gobastion" {
				return "gobastion:x:1001:alice,former\n", nil
			}

			var names []string
			for name := range a.members {
				names = append(names, name)
			}
			sort.Strings(names)
			return recording.AuditorGroup + ":x:1005:" + strings.Join(names, ",") + "\n", nil
		}
		return "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1001::/home/alice:/bin/sh\nformer:x:1002:1001::/home/former:/bin/sh\n", nil
	case "/usr/sbin/addgroup":
		a.members[args[0]] = true
		return "", nil
	case "/usr/sbin/delgroup":
		delete(a.members, args[0])
		return "", nil
	case "/usr/bin/pkill":
		if a.failKill {
			return "", errors.New("kill refused")
		}
		return "", nil
	case "/usr/bin/pgrep":
		return "", a.noProcess
	}
	return "", fmt.Errorf("unexpected command: %s", name)
}
func auditorFixture(t *testing.T) (*Syncer, *auditorAdapter, string) {
	t.Helper()
	db, _ := newSyncTestDB(t)
	adapter := &auditorAdapter{MockAdapter: osadapter.NewMockAdapter(), members: make(map[string]bool), noProcess: exec.Command("sh", "-c", "exit 1").Run()}
	s := New(db, adapter, *slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.reconcileAuditorAccess = true
	s.lookupUser = func(name string) (*osuser.User, error) {
		switch name {
		case "alice":
			return &osuser.User{Username: name, Uid: "1000", Gid: "1001"}, nil
		case "former":
			return &osuser.User{Username: name, Uid: "1002", Gid: "1001"}, nil
		}
		return nil, osuser.UnknownUserError(name)
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	s.openAuditorJournal = func() (*auditorJournal, error) {
		r, e := os.OpenRoot(base)
		return &auditorJournal{root: r, owner: uint32(os.Geteuid())}, e
	}
	return s, adapter, base
}
func TestAuditorsUseFreshPolicyAndRetryFailedRevocation(t *testing.T) {
	s, a, base := auditorFixture(t)
	actor := models.User{Username: "alice", Role: models.RoleAdmin, Enabled: true}
	if err := s.db.Create(&actor).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileAuditors(); err != nil {
		t.Fatal(err)
	}
	if !a.members["alice"] {
		t.Fatal("enabled administrator not granted read group")
	}
	if err := s.db.Model(&actor).Update("role", models.RoleUser).Error; err != nil {
		t.Fatal(err)
	}
	a.failKill = true
	if err := s.reconcileAuditors(); err == nil {
		t.Fatal("failed process revocation returned success")
	}
	if a.members["alice"] {
		t.Fatal("demoted administrator membership remains")
	}
	if _, err := os.Stat(filepath.Join(base, "alice")); err != nil {
		t.Fatal("failed revocation lost retry marker:", err)
	}
	a.failKill = false
	if err := s.reconcileAuditors(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "alice")); !os.IsNotExist(err) {
		t.Fatal("completed revocation retained marker:", err)
	}
	kills := 0
	for _, c := range a.calls {
		if strings.HasPrefix(c, "/usr/bin/pkill") {
			kills++
		}
	}
	if kills != 2 {
		t.Fatalf("revocation was not retried: %d kills", kills)
	}
	if a.members["alice"] {
		t.Fatal("demoted actor was re-added")
	}
}
func TestAuditorsRemoveStaleMembershipAndExcludeDisabledAdmins(t *testing.T) {
	s, a, _ := auditorFixture(t)
	a.members["former"] = true
	if err := s.db.Create(&models.User{Username: "alice", Role: models.RoleAdmin, Enabled: false}).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Model(&models.User{}).Where("username = ?", "alice").Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileAuditors(); err != nil {
		t.Fatal(err)
	}
	if len(a.members) != 0 {
		t.Fatalf("unauthorized members: %v", a.members)
	}
}
func TestRecordingProvisionFailurePreventsPublication(t *testing.T) {
	db, _ := newSyncTestDB(t)
	adapter := osadapter.NewMockAdapter()
	adapter.HomeExists = true
	s := New(db, adapter, *slog.New(slog.NewTextHandler(io.Discard, nil)))
	refused := errors.New("unsafe existing recording tree")
	s.provisionRecording = func(string, string) error { return refused }
	if err := s.createUserFromDBUnlocked(models.User{Username: "alice", Enabled: true}); !errors.Is(err, refused) {
		t.Fatalf("lost provision failure: %v", err)
	}
	if len(adapter.UpdatedSudoers) != 0 {
		t.Fatal("published privilege after recording failure")
	}
}
func TestAuditorJournalRejectsUnsafeMarkersAndRecoversPublication(t *testing.T) {
	for _, scenario := range []string{"symlink", "mode", "hardlink", "invalid uid", "interrupted publication"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, base := auditorFixture(t)
			j, err := s.openAuditorJournal()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = j.close() }()
			target := filepath.Join(base, "alice")
			switch scenario {
			case "symlink":
				err = os.Symlink("/dev/null", target)
			case "mode":
				err = os.WriteFile(target, []byte("1000\n"), 0644)
			case "hardlink":
				err = os.WriteFile(target, []byte("1000\n"), 0600)
				if err == nil {
					err = os.Link(target, filepath.Join(base, "former"))
				}
			case "invalid uid":
				err = os.WriteFile(target, []byte("0\n"), 0600)
			case "interrupted publication":
				tmp := filepath.Join(base, ".pending-fixture")
				err = os.WriteFile(tmp, []byte("1000\n"), 0600)
				if err == nil {
					err = os.Link(tmp, target)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			pending, err := j.load()
			if scenario == "interrupted publication" {
				if err != nil || pending["alice"] != "1000" {
					t.Fatalf("failed recovery: %v %v", pending, err)
				}
				if err = j.clear("alice", "1000"); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe marker accepted")
			}
		})
	}
}
func TestPendingAuditorRejectsRecycledUID(t *testing.T) {
	s, _, _ := auditorFixture(t)
	if _, err := s.pendingAuditorAccount("alice", "1002", 1005); err == nil {
		t.Fatal("changed account UID accepted")
	}
	s.lookupUID = func(string) (*osuser.User, error) { return &osuser.User{Username: "replacement", Uid: "1003"}, nil }
	if _, err := s.pendingAuditorAccount("deleted", "1003", 1005); err == nil {
		t.Fatal("reassigned UID accepted")
	}
}

func TestAuditorProcessVerificationDistinguishesZombiesAndActiveCredentials(t *testing.T) {
	for _, tc := range []struct {
		state, uid string
		active     bool
	}{
		{"S", "1000", true}, {"D", "1000", true}, {"Z", "1000", false}, {"X", "1000", false}, {"S", "1002", false},
	} {
		raw := "Name:\tfixture\nState:\t" + tc.state + " (test)\nUid:\t" + tc.uid + "\t" + tc.uid + "\t" + tc.uid + "\t" + tc.uid + "\n"
		active, err := auditorStatusRunning(raw, "1000")
		if err != nil || active != tc.active {
			t.Fatalf("process %q %s: active=%t error=%v", tc.state, tc.uid, active, err)
		}
	}
	if _, err := auditorStatusRunning("State: S\nUid: invalid\n", "1000"); err == nil {
		t.Fatal("malformed credentials accepted")
	}
}

func TestAuditorAccountInventoryRejectsAmbiguousUnixIdentities(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		bad       bool
	}{
		{"valid", "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1001::/home/alice:/bin/sh\n", false},
		{"UID alias", "alice:x:1000:1001::/home/alice:/bin/sh\nbob:x:1000:1001::/home/bob:/bin/sh\n", true},
		{"name alias", "alice:x:1000:1001::/home/alice:/bin/sh\nalice:x:1002:1001::/home/alice:/bin/sh\n", true},
		{"duplicate row", "alice:x:1000:1001::/home/alice:/bin/sh\nalice:x:1000:1001::/home/alice:/bin/sh\n", true},
		{"primary auditor", "alice:x:1000:1005::/home/alice:/bin/sh\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := rejectAuditorPrimaryGroup(tc.raw, 1005); (err != nil) != tc.bad {
				t.Fatalf("error=%v want refusal=%t", err, tc.bad)
			}
		})
	}
}

func TestRecordingAuditorsRejectHistoricallyReusedActiveNamesBeforeMutation(t *testing.T) {
	for _, historicalName := range []string{"alice", "Alice"} {
		t.Run(historicalName, func(t *testing.T) {
			s, adapter, _ := auditorFixture(t)
			former := models.User{Username: historicalName, Role: models.RoleAdmin, Enabled: true}
			if err := s.db.Create(&former).Error; err != nil {
				t.Fatal(err)
			}
			if err := s.db.Delete(&former).Error; err != nil {
				t.Fatal(err)
			}
			if err := s.db.Create(&models.User{Username: "alice", Role: models.RoleAdmin, Enabled: true}).Error; err != nil {
				t.Fatal(err)
			}
			if err := s.reconcileAuditors(); err == nil {
				t.Fatal("reused historical identity accepted")
			}
			if len(adapter.calls) != 0 || len(adapter.members) != 0 {
				t.Fatal("OS access changed before identity ambiguity rejected")
			}
		})
	}
}
