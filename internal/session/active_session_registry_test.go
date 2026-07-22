package session

import (
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestRegisterActiveSessionEnforcesInstanceLimitAndCleansStaleRows(t *testing.T) {
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)

	cfg := config.DefaultConfig()
	cfg.Session.MaxConcurrentSessions = 1
	config.SetForTesting(cfg)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(&models.ActiveSession{}); err != nil {
		t.Fatalf("migrate active sessions: %v", err)
	}

	user := &models.User{Username: "alice"}
	stale := models.ActiveSession{
		SessionID:  "stale-session",
		InstanceID: config.InstanceID(),
		Username:   "bob",
		PID:        0,
		Kind:       "ssh",
	}
	if err := db.Create(&stale).Error; err != nil {
		t.Fatalf("create stale session: %v", err)
	}

	release, err := registerActiveSession(db, user, "live-session", "ssh")
	if err != nil {
		t.Fatalf("register first active session: %v", err)
	}
	defer release()

	var count int64
	if err := db.Model(&models.ActiveSession{}).Count(&count).Error; err != nil {
		t.Fatalf("count active sessions: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 active session after stale cleanup, got %d", count)
	}

	if _, err := registerActiveSession(db, user, "blocked-session", "db"); err == nil {
		t.Fatal("expected concurrency limit error, got nil")
	}
}
