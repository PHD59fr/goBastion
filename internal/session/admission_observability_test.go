package session

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/logger"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type admissionCounter struct{ count int64 }

func (c *admissionCounter) Record(_ context.Context, metric string, delta int64) error {
	if metric == "gobastion_access_denied_total" {
		c.count += delta
	}
	return nil
}

func (*admissionCounter) ObserveSyncDuration(context.Context, time.Duration) error { return nil }

func TestRevokedAdmissionCountsOneDenial(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("SSH sessions run as a non-root account")
	}
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Splash.Enabled = false
	config.SetForTesting(cfg)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	name, err := currentSystemUser()
	if err != nil {
		t.Fatal(err)
	}
	actor := models.User{Username: name, Enabled: true, Role: models.RoleUser}
	if err := db.Create(&actor).Error; err != nil {
		t.Fatal(err)
	}
	// Revoke the account after the initial session lookup and before the
	// admission refresh, exercising the actual concurrent-revocation path.
	queries := 0
	if err := db.Callback().Query().Before("gorm:query").Register("test:revoke_before_refresh", func(tx *gorm.DB) {
		if tx.Statement.Table != "users" {
			return
		}
		queries++
		if queries == 2 {
			if err := tx.Session(&gorm.Session{NewDB: true}).Exec("UPDATE users SET enabled = ? WHERE id = ?", false, actor.ID).Error; err != nil {
				_ = tx.AddError(err)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}

	observer := &admissionCounter{}
	logger.SetEventObserver(observer)
	t.Cleanup(func() { logger.SetEventObserver(nil) })
	log := logger.NewLogger()
	previous := slog.Default()
	slog.SetDefault(log)
	t.Cleanup(func() { slog.SetDefault(previous) })
	oldArgs := os.Args
	os.Args = []string{"gobastion", "deploy@fixture"}
	t.Cleanup(func() { os.Args = oldArgs })
	t.Setenv("GOB_SESSION_ID", "")
	_, stderr, _, captureErr := captureOutput(func() error { Run(db, log); return nil })
	if captureErr != nil {
		t.Fatal(captureErr)
	}
	if queries != 2 || stderr == "" {
		t.Fatalf("admission refresh did not deny revoked account: queries=%d stderr=%q", queries, stderr)
	}
	if observer.count != 1 {
		t.Fatalf("access-denied counter = %d, want 1 for one denied admission", observer.count)
	}
}
