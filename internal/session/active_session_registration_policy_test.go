package session

import (
	"path/filepath"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func admissionPolicyFixture(t *testing.T) (*gorm.DB, *models.User) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "admission.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.AutoMigrate(&models.User{}, &models.ActiveSession{}); err != nil {
		t.Fatal(err)
	}
	actor := createAdmissionActor(t, db)
	return db, actor
}

func TestSessionRegistrationRejectsChangedAuthenticatedActor(t *testing.T) {
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	for _, change := range []struct {
		name   string
		mutate func(*gorm.DB, *models.User) error
	}{
		{"disabled", func(db *gorm.DB, u *models.User) error { return db.Model(u).Update("enabled", false).Error }},
		{"deleted", func(db *gorm.DB, u *models.User) error {
			return db.Model(u).Update("deleted_at", time.Now()).Error
		}},
		{"system", func(db *gorm.DB, u *models.User) error { return db.Model(u).Update("system_user", true).Error }},
		{"renamed", func(db *gorm.DB, u *models.User) error { return db.Model(u).Update("username", "renamed").Error }},
		{"role", func(db *gorm.DB, u *models.User) error { return db.Model(u).Update("role", models.RoleAdmin).Error }},
		{"osh-only", func(db *gorm.DB, u *models.User) error { return db.Model(u).Update("osh_only", true).Error }},
		{"password", func(db *gorm.DB, u *models.User) error {
			return db.Model(u).Update("password_hash", "changed-hash").Error
		}},
		{"totp", func(db *gorm.DB, u *models.User) error {
			return db.Model(u).Updates(map[string]any{"totp_enabled": true, "totp_secret": "changed-secret"}).Error
		}},
		{"disable-reenable", func(db *gorm.DB, u *models.User) error {
			return db.Model(u).Updates(map[string]any{"enabled": true, "revocation_epoch": gorm.Expr("revocation_epoch + 1")}).Error
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			db, actor := admissionPolicyFixture(t)
			authenticated := *actor
			if err := change.mutate(db, actor); err != nil {
				t.Fatal(err)
			}
			if release, err := registerActiveSession(db, &authenticated, "changed-actor", "ssh"); err == nil {
				release()
				t.Fatal("changed actor was admitted")
			}
			var count int64
			if err := db.Model(&models.ActiveSession{}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("denied admission inserted %d session rows", count)
			}
		})
	}
}

func TestSessionRegistrationPoolWaitHasDeadline(t *testing.T) {
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	db, actor := admissionPolicyFixture(t)
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	held, err := pool.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	started := time.Now()
	if release, err := registerActiveSession(db, actor, "blocked-admission", "ssh"); err == nil {
		release()
		t.Fatal("admission succeeded while its only database connection was held")
	}
	if elapsed := time.Since(started); elapsed > activeSessionAdmissionTimeout+2*time.Second {
		t.Fatalf("admission exceeded its timeout: %v", elapsed)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Model(&models.ActiveSession{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("timed-out admission inserted %d session rows", count)
	}
}
