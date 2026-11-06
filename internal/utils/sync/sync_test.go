package sync

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	if err := db.Create(&models.SshHostKey{Type: "ed25519", PrivateKey: []byte("test"), PublicKey: []byte("test")}).Error; err != nil {
		t.Fatal(err)
	}
	return db, cfg
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
			if err := s.EnforceFromDB(); err != nil {
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
