package tty

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"goBastion/internal/config"
	"gorm.io/gorm"

	"goBastion/internal/models"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.IngressKey{}, &models.SelfEgressKey{},
		&models.GroupEgressKey{}, &models.SelfAccess{}, &models.GroupAccess{},
		&models.Group{}, &models.UserGroup{}, &models.Aliases{},
		&models.KnownHostsEntry{}, &models.PIVTrustAnchor{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestList_NoArgs(t *testing.T) {
	db := newTestDB(t)
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := config.Get()
	copyCfg := *cfg
	copyCfg.Paths = cfg.Paths
	copyCfg.Paths.TtyrecDir = filepath.Join(t.TempDir(), "ttyrec")
	config.SetForTesting(&copyCfg)
	t.Cleanup(func() { config.SetForTesting(cfg) })

	if err := List(db, &user, []string{}); err != nil {
		t.Fatalf("expected no error when recordings dir is missing, got %v", err)
	}
}

func TestList_DoesNotMutateLegacyTTYRecs(t *testing.T) {
	db := newTestDB(t)
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	baseDir := filepath.Join(t.TempDir(), "ttyrec")
	serverDir := filepath.Join(baseDir, "alice", "db.example.internal")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatalf("mkdir recordings dir: %v", err)
	}
	rawRecording := filepath.Join(serverDir, "root.db.example.internal:22_2026-07-21_12-30-00.ttyrec")
	if err := os.WriteFile(rawRecording, []byte("legacy ttyrec"), 0o644); err != nil {
		t.Fatalf("write legacy ttyrec: %v", err)
	}

	cfg := config.Get()
	copyCfg := *cfg
	copyCfg.Paths = cfg.Paths
	copyCfg.Paths.TtyrecDir = baseDir
	config.SetForTesting(&copyCfg)
	t.Cleanup(func() { config.SetForTesting(cfg) })

	if err := List(db, &user, []string{}); err != nil {
		t.Fatalf("list recordings: %v", err)
	}
	if _, err := os.Stat(rawRecording); err != nil {
		t.Fatalf("expected legacy ttyrec to remain untouched, got stat error %v", err)
	}
	if _, err := os.Stat(rawRecording + ".gz"); !os.IsNotExist(err) {
		t.Fatalf("expected ttyList not to create gzip file, got err=%v", err)
	}
}
