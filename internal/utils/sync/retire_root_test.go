package sync

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/recording"
)

func TestRootRecordingAccountRetirementWorkflow(t *testing.T) {
	if os.Getenv("GOB_TEST_ROOT_SSH_PUBLISH") != "1" {
		t.Skip("requires dedicated root container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	db, cfg := newSyncTestDB(t)
	if err := db.AutoMigrate(&models.ActiveSession{}); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("/run", "gobastion-retire-workflow-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	if err = os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	cfg.Paths.HomeBaseDir = filepath.Join(base, "homes")
	if err = os.Mkdir(cfg.Paths.HomeBaseDir, 0755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(cfg.Paths.HomeBaseDir, "victim")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(home, 1000, 1001); err != nil {
		t.Fatal(err)
	}
	cfg.Paths.TtyrecDir = filepath.Join(base, "archive")
	if err = os.Mkdir(cfg.Paths.TtyrecDir, 0751); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(cfg.Paths.TtyrecDir, 0, 1001); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(cfg.Paths.TtyrecDir, 0751); err != nil {
		t.Fatal(err)
	}
	if err = recording.ProvisionAccount(cfg.Paths.TtyrecDir, "victim"); err != nil {
		t.Fatal(err)
	}
	victim := models.User{Username: "victim", Role: models.RoleUser, Enabled: true}
	if err = db.Create(&victim).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Create(&models.User{Username: "administrator", Role: models.RoleAdmin, Enabled: true}).Error; err != nil {
		t.Fatal(err)
	}
	if err = db.Delete(&victim).Error; err != nil {
		t.Fatal(err)
	}
	session := models.ActiveSession{SessionID: "drain-required", InstanceID: "other-instance", Username: "victim", PID: 999999, Kind: "ssh"}
	if err = db.Create(&session).Error; err != nil {
		t.Fatal(err)
	}
	s := New(db, osadapter.NewLinuxAdapter(), *slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err = s.SyncUserByName("victim"); err == nil {
		t.Fatal("retired account before registered sessions drained")
	}
	info, err := os.Stat(filepath.Join(cfg.Paths.TtyrecDir, "victim"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Sys().(*syscall.Stat_t).Uid != 1000 {
		t.Fatal("drain denial modified archive")
	}
	if err = db.Delete(&session).Error; err != nil {
		t.Fatal(err)
	}
	if err = s.SyncUserByName("victim"); err != nil {
		t.Fatal(err)
	}
	if err = s.SyncUserByName("victim"); err != nil {
		t.Fatal("retirement not idempotent:", err)
	}
	actual, err := s.lookupUser("victim")
	if err != nil || actual.Uid != "1000" {
		t.Fatal("UID reservation was lost:", err)
	}
	keys, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil || len(keys) != 0 {
		t.Fatal("retirement did not remove SSH keys:", err)
	}
	info, err = os.Stat(filepath.Join(cfg.Paths.TtyrecDir, "victim"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("retired recording boundary not root-owned")
	}
}
