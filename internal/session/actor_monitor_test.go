package session

import (
	"database/sql"
	"testing"
	"time"

	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func revocationFixture(t *testing.T) (*gorm.DB, *sql.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.AutoMigrate(&models.ActiveSession{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.ActiveSession{
		SessionID: "revoked-session", InstanceID: "fixture", Username: "alice", PID: 1, Kind: "ssh",
	}).Error; err != nil {
		t.Fatal(err)
	}
	return db, pool
}

func TestTerminateRevokedSessionDeletesRegistryBeforeExit(t *testing.T) {
	db, _ := revocationFixture(t)
	exitCode := -1
	terminateRevokedSession(db, "revoked-session", nil, time.Second, func(code int) {
		exitCode = code
	})
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	var count int64
	if err := db.Model(&models.ActiveSession{}).Where("session_id = ?", "revoked-session").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("revoked session registration was not deleted")
	}
}

func TestTerminateRevokedSessionIsBoundedByBlockedDatabase(t *testing.T) {
	db, pool := revocationFixture(t)
	held, err := pool.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()

	exited := make(chan struct{})
	start := time.Now()
	go func() {
		terminateRevokedSession(db, "revoked-session", nil, 100*time.Millisecond, func(code int) {
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			close(exited)
		})
	}()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation was blocked by an unavailable database")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("revocation took %v, want bounded exit", elapsed)
	}
}
