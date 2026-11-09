package sync

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"goBastion/internal/utils/cryptokey"
	"io"
	"log/slog"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type processAdapter struct {
	*osadapter.MockAdapter
	output string
	err    error
	args   []string
}

func (a *processAdapter) ExecCommand(name string, args ...string) (string, error) {
	if name != "pgrep" {
		return "", errors.New("unexpected command: " + name)
	}
	a.args = append([]string{name}, args...)
	return a.output, a.err
}

func newSyncTestDB(t *testing.T) (*gorm.DB, *config.Config) {
	t.Helper()
	t.Setenv("EGRESS_ENC_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Paths.HomeBaseDir = t.TempDir()
	cfg.Paths.SshHostKeyDir = t.TempDir()
	config.SetForTesting(cfg)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.UserGroup{}, &models.IngressKey{}, &models.KnownHostsEntry{}, &models.SshHostKey{}, &models.BastionInstance{}); err != nil {
		t.Fatal(err)
	}
	encrypted, err := cryptokey.Encrypt("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.SshHostKey{Type: "ed25519", PrivateKey: []byte(encrypted), PublicKey: []byte("test")}).Error; err != nil {
		t.Fatal(err)
	}
	return db, cfg
}

func TestEnforceReportsHostKeyAndPrivilegeReconciliationFailures(t *testing.T) {
	for _, failure := range []string{"encrypted_host_key", "sudoers"} {
		t.Run(failure, func(t *testing.T) {
			database, _ := newSyncTestDB(t)
			adapter := osadapter.NewMockAdapter()
			adapter.HomeExists = true
			if failure == "encrypted_host_key" {
				if err := database.Model(&models.SshHostKey{}).Where("type = ?", "ed25519").Update("private_key", []byte("gob:v2:unknown:corrupt")).Error; err != nil {
					t.Fatal(err)
				}
			} else {
				if err := database.Create(&models.User{Username: "fixture", Role: models.RoleUser, Enabled: true}).Error; err != nil {
					t.Fatal(err)
				}
				adapter.ErrUpdateSudoers = errors.New("privileged helper refused update")
			}
			var logs bytes.Buffer
			if err := New(database, adapter, *slog.New(slog.NewJSONHandler(&logs, nil))).EnforceFromDB(); err == nil {
				t.Fatal("unsafe partial synchronization reported success")
			}
			if strings.Contains(logs.String(), `"msg":"sync_complete"`) {
				t.Fatal("failed sync emitted a completion event")
			}
			if !strings.Contains(logs.String(), `"success":false`) {
				t.Fatal("failed synchronization had no result observation")
			}
		})
	}
}

func TestSyncRemovesOnlyIdleOrphanAccounts(t *testing.T) {
	noProcesses := exec.Command("sh", "-c", "exit 1").Run()
	for _, tc := range []struct {
		name, output string
		err          error
		remove       bool
	}{
		{name: "no processes", err: noProcesses, remove: true},
		{name: "active sessions", output: "1234\n"},
		{name: "process lookup failed", err: errors.New("pgrep unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, cfg := newSyncTestDB(t)
			if err := os.Mkdir(filepath.Join(cfg.Paths.HomeBaseDir, "orphan"), 0700); err != nil {
				t.Fatal(err)
			}
			adapter := &processAdapter{MockAdapter: osadapter.NewMockAdapter(), output: tc.output, err: tc.err}
			s := New(db, adapter, *slog.New(slog.NewTextHandler(io.Discard, nil)))
			err := s.EnforceFromDB()
			if tc.name == "process lookup failed" {
				if err == nil {
					t.Fatal("failed process lookup reported successful synchronization")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(adapter.args, []string{"pgrep", "-u", "orphan"}) {
				t.Fatalf("incorrect pgrep argv: %q", adapter.args)
			}
			if got := len(adapter.DeletedUsers) > 0; got != tc.remove {
				t.Fatalf("removed=%t, want %t", got, tc.remove)
			}
		})
	}
}

func TestSyncRevokesDisabledSessionsAndIngressKeys(t *testing.T) {
	db, cfg := newSyncTestDB(t)
	enabled := models.User{Username: "enabled", Role: models.RoleUser, Enabled: true}
	disabled := models.User{Username: "disabled", Role: models.RoleAdmin, Enabled: true}
	for _, u := range []*models.User{&enabled, &disabled} {
		if err := db.Create(u).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Model(&disabled).Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.IngressKey{UserID: disabled.ID, Key: "ssh-ed25519 test", Type: "ed25519", Fingerprint: "test"}).Error; err != nil {
		t.Fatal(err)
	}
	adapter := osadapter.NewMockAdapter()
	adapter.HomeExists = true
	if err := New(db, adapter, *slog.New(slog.NewTextHandler(io.Discard, nil))).EnforceFromDB(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(adapter.TerminatedUsers, []string{"disabled"}) {
		t.Fatalf("wrong sessions terminated: %v", adapter.TerminatedUsers)
	}
	keys, err := os.ReadFile(filepath.Join(cfg.Paths.HomeBaseDir, "disabled", ".ssh", "authorized_keys"))
	if err != nil || len(keys) != 0 {
		t.Fatalf("disabled account still has ingress keys: %q, %v", keys, err)
	}
}

func TestInactiveSweepPreservesMostRecentAdministrator(t *testing.T) {
	db, cfg := newSyncTestDB(t)
	cfg.Account.MaxInactiveDays = 1
	for i, name := range []string{"old-admin", "recent-admin", "regular"} {
		u := models.User{Username: name, Enabled: true, Role: models.RoleAdmin, LastLoginAt: time.Now().Add(-time.Duration(20-i) * 24 * time.Hour)}
		if i == 2 {
			u.Role = models.RoleUser
		}
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := New(db, osadapter.NewMockAdapter(), *slog.New(slog.NewTextHandler(io.Discard, nil))).disableInactiveUsers(); err != nil {
		t.Fatal(err)
	}
	var users []models.User
	db.Find(&users)
	for _, u := range users {
		if u.Enabled != (u.Username == "recent-admin") {
			t.Fatalf("wrong enabled state for %s", u.Username)
		}
	}
}

func TestSyncUserSnapshotsAfterLockAndReleasesOnFailure(t *testing.T) {
	db, _ := newSyncTestDB(t)
	user := models.User{Username: "fixture", Role: models.RoleAdmin, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	adapter := osadapter.NewMockAdapter()
	s := New(db, adapter, *slog.New(slog.NewTextHandler(io.Discard, nil)))
	entered, proceed, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.acquireLock = func(context.Context) (func() error, error) {
		close(entered)
		<-proceed
		return func() error { close(released); return nil }, nil
	}
	done := make(chan error, 1)
	go func() { done <- s.SyncUserByName("fixture") }()
	<-entered
	if len(adapter.CreatedUsers) != 0 {
		t.Fatal("OS account created before lock acquisition")
	}
	if err := db.Model(&user).Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-released
	if len(adapter.CreatedUsers) != 1 || adapter.CreatedUsers[0] != "fixture" {
		t.Fatalf("unexpected creations: %v", adapter.CreatedUsers)
	}
	if len(adapter.UpdatedSudoers) != 1 || adapter.UpdatedSudoers[0].Enabled {
		t.Fatalf("stale user applied: %+v", adapter.UpdatedSudoers)
	}
	if len(adapter.TerminatedUsers) != 1 || adapter.TerminatedUsers[0] != "fixture" {
		t.Fatalf("disabled reconciliation must terminate sessions: %v", adapter.TerminatedUsers)
	}

	terminationErr := errors.New("termination failed")
	adapter.ErrTerminateUserSessions = terminationErr
	adapter.UpdatedSudoers = nil
	released = make(chan struct{})
	s.acquireLock = func(context.Context) (func() error, error) {
		return func() error { close(released); return nil }, nil
	}
	if err := s.SyncUserByName("fixture"); !errors.Is(err, terminationErr) {
		t.Fatalf("session termination failure was not returned: %v", err)
	}
	select {
	case <-released:
	default:
		t.Fatal("lock not released after session termination failure")
	}
	if len(adapter.UpdatedSudoers) != 0 {
		t.Fatal("continued reconciliation after session termination failure")
	}
	adapter.ErrTerminateUserSessions = nil

	s.acquireLock = func(context.Context) (func() error, error) {
		return func() error { return errors.New("unlock failed") }, nil
	}
	if err := s.SyncUserByName("fixture"); err == nil || !strings.Contains(err.Error(), "unlock failed") {
		t.Fatalf("release failure was not returned: %v", err)
	}

	adapter.ErrUpdateSudoers = errors.New("failed")
	released = make(chan struct{})
	s.acquireLock = func(context.Context) (func() error, error) { return func() error { close(released); return nil }, nil }
	if err := s.SyncUserByName("fixture"); err == nil {
		t.Fatal("expected update failure")
	}
	select {
	case <-released:
	default:
		t.Fatal("lock not released on failure")
	}
	s.acquireLock = func(context.Context) (func() error, error) { return nil, errors.New("lock unavailable") }
	adapter.UpdatedSudoers = nil
	if err := s.SyncUserByName("fixture"); err == nil {
		t.Fatal("expected lock failure")
	}
	if len(adapter.UpdatedSudoers) != 0 {
		t.Fatal("applied state without lock")
	}
}

func TestSyncUserRejectsSystemAndInvalidAccounts(t *testing.T) {
	db, _ := newSyncTestDB(t)
	adapter := osadapter.NewMockAdapter()
	s := New(db, adapter, *slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.acquireLock = func(context.Context) (func() error, error) { return func() error { return nil }, nil }
	u := models.User{Username: "fixture", SystemUser: true}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.SyncUserByName("fixture"); err == nil {
		t.Fatal("system DB user accepted")
	}
	if err := db.Model(&u).Update("system_user", false).Error; err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"0", "999", "65000", "65534", "invalid"} {
		s.lookupUser = func(string) (*osuser.User, error) { return &osuser.User{Uid: uid}, nil }
		if err := s.SyncUserByName("fixture"); err == nil {
			t.Fatalf("UID %s accepted", uid)
		}
	}
	s.lookupUser = func(string) (*osuser.User, error) { return nil, errors.New("lookup failed") }
	if err := s.SyncUserByName("fixture"); err == nil {
		t.Fatal("lookup failure accepted")
	}
	for _, name := range []string{"nobody", "gobastion", "Fixture", "../root"} {
		if err := s.SyncUserByName(name); err == nil {
			t.Fatalf("invalid or reserved name %q accepted", name)
		}
	}
	if len(adapter.CreatedUsers) != 0 || len(adapter.UpdatedSudoers) != 0 {
		t.Fatal("effects occurred for rejected account")
	}
}
