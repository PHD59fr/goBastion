package session

import (
	"os"
	"strings"
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

func TestActiveSessionProcessIdentityRejectsRecycledPID(t *testing.T) {
	identity, err := processIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if identity == "" {
		t.Fatal("empty identity")
	}
	for _, tc := range []struct {
		name, identity string
		want           bool
	}{
		{"same process", identity, true},
		{"recycled PID", "v1:" + strings.Repeat("0", 64), false},
		{"live legacy process", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := activeSessionProcessAlive(models.ActiveSession{PID: os.Getpid(), ProcessIdentity: tc.identity}); got != tc.want {
				t.Fatalf("active = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCleanupStaleSessionsMatchesProcessIdentityAndInstance(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.ActiveSession{}); err != nil {
		t.Fatal(err)
	}
	identity, err := processIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []models.ActiveSession{
		{SessionID: "live", InstanceID: "local", PID: os.Getpid(), ProcessIdentity: identity},
		{SessionID: "recycled", InstanceID: "local", PID: os.Getpid(), ProcessIdentity: "old-process"},
		{SessionID: "legacy", InstanceID: "local", PID: os.Getpid()},
		{SessionID: "remote", InstanceID: "remote", PID: 0},
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := cleanupStaleActiveSessions(db, "local"); err != nil {
		t.Fatal(err)
	}
	var rows []models.ActiveSession
	if err := db.Order("session_id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, row := range rows {
		ids = append(ids, row.SessionID)
	}
	if got := strings.Join(ids, ","); got != "legacy,live,remote" {
		t.Fatalf("remaining sessions = %s", got)
	}
}

func TestProcessStartCounterHandlesParenthesizedCommand(t *testing.T) {
	stat := "123 (a ) tricky (command) S " + strings.Repeat("0 ", 18) + "4242 0"
	if got, err := processStartCounter(stat); err != nil || got != "4242" {
		t.Fatalf("start = %q, err = %v", got, err)
	}
	for _, invalid := range []string{"", "123 (name)", strings.Replace(stat, "4242", "invalid", 1)} {
		if _, err := processStartCounter(invalid); err == nil {
			t.Fatalf("accepted invalid stat %q", invalid)
		}
	}
}

func TestActiveSessionIdentityMigrationPreservesLegacyRows(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE active_sessions (
		session_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, username TEXT NOT NULL,
		p_id INTEGER NOT NULL, kind TEXT NOT NULL, created_at DATETIME, updated_at DATETIME
	)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO active_sessions (session_id, instance_id, username, p_id, kind) VALUES (?, ?, ?, ?, ?)", "legacy", "local", "alice", os.Getpid(), "ssh").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.ActiveSession{}); err != nil {
		t.Fatal(err)
	}
	var row models.ActiveSession
	if err := db.First(&row, "session_id = ?", "legacy").Error; err != nil {
		t.Fatal(err)
	}
	if row.ProcessIdentity != "" || !activeSessionProcessAlive(row) {
		t.Fatal("migration lost conservative accounting for a live legacy session")
	}
}
