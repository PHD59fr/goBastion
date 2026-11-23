package session

import (
	"os"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func createAdmissionActor(t *testing.T, db *gorm.DB) *models.User {
	t.Helper()
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	u := &models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

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

	user := createAdmissionActor(t, db)
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
	release()
	release() // Interactive teardown and its deferred cleanup may both run.
	if err := db.Model(&models.ActiveSession{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("released session registration remains")
	}
}

func TestActiveSessionReleaseIsBoundedByBlockedDatabase(t *testing.T) {
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	db, pool := revocationFixture(t)
	actor := createAdmissionActor(t, db)
	release, err := registerActiveSession(db, actor, "finished-session", "ssh")
	if err != nil {
		t.Fatal(err)
	}
	held, err := pool.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	done := make(chan struct{})
	started := time.Now()
	go func() {
		release()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(activeSessionCleanupTimeout + 2*time.Second):
		t.Fatal("normal session release was blocked by the saturated database pool")
	}
	if elapsed := time.Since(started); elapsed > activeSessionCleanupTimeout+time.Second {
		t.Fatalf("normal session release took %v", elapsed)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Model(&models.ActiveSession{}).Where("session_id = ?", "finished-session").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("timed-out cleanup should retain the registration for stale-process cleanup")
	}
	release()
	if err := db.Model(&models.ActiveSession{}).Where("session_id = ?", "finished-session").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("cleanup retry did not remove the registration")
	}
}

func TestActiveSessionReleaseDoesNotWaitForCancellationIgnoringCallback(t *testing.T) {
	db, _ := revocationFixture(t)
	entered := make(chan struct{})
	unblock := make(chan struct{})
	finished := make(chan struct{})
	defer close(unblock)
	if err := db.Callback().Delete().Before("gorm:begin_transaction").Register("test:block_session_release", func(*gorm.DB) {
		close(entered)
		<-unblock
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Callback().Delete().After("gorm:commit_or_rollback_transaction").Register("test:finish_session_release", func(*gorm.DB) {
		close(finished)
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		releaseActiveSession(db, "revoked-session", 100*time.Millisecond)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not reach the blocking callback")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup waited for a callback that ignored cancellation")
	}
	// Release the callback and join the worker before the fixture closes its pool.
	unblock <- struct{}{}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cleanup worker did not finish after the callback was released")
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
