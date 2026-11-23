package session

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestSessionActorMonitorLateSuccessfulQueryCannotBypassDeadline(t *testing.T) {
	const helperEnv = "GOB_TEST_LATE_SESSION_ACTOR_QUERY"
	const completedMarker = "healthy actor lookup completed after deadline"
	if os.Getenv(helperEnv) == "1" {
		db, _, actor := actorMonitorFixture(t)
		completed := make(chan struct{})
		if err := db.Callback().Query().After("gorm:query").Register("test:session_actor_late_query", func(tx *gorm.DB) {
			fresh, ok := tx.Statement.Dest.(*models.User)
			if tx.Error != nil || !ok || fresh.ID != actor.ID || !fresh.Enabled {
				return
			}
			select {
			case <-completed:
				// Reaching another poll means the expired successful lookup
				// left the session alive instead of terminating it.
				os.Exit(42)
			default:
			}
			// Keep the successful result after its deadline, as a driver or
			// callback can do even when it returns no query error.
			<-tx.Statement.Context.Done()
			_, _ = os.Stdout.WriteString(completedMarker + "\n")
			close(completed)
		}); err != nil {
			t.Fatal(err)
		}
		startSessionActorMonitor(context.Background(), db, actor.ID, "", actor, nil)
		// A revoked monitor exits the process itself. Keep a distinct sentinel
		// for a worker that never polls or terminates.
		<-time.After(4 * time.Second)
		os.Exit(43)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSessionActorMonitorLateSuccessfulQueryCannotBypassDeadline$")
	command.Env = append(os.Environ(), helperEnv+"=1")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("actor monitor subprocess did not finish: %v; output: %s", ctx.Err(), output)
	}
	if !strings.Contains(string(output), completedMarker) {
		t.Fatalf("actor lookup did not reach its deadline with a healthy result: %v; output: %s", err, output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("late successful actor query did not terminate the session: %v; output: %s", err, output)
	}
}

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
