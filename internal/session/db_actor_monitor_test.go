package session

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func actorMonitorFixture(t *testing.T) (*gorm.DB, *sql.DB, models.User) {
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
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	actor := models.User{Username: "db-monitor", Enabled: true, Role: models.RoleUser}
	if err := db.Create(&actor).Error; err != nil {
		t.Fatal(err)
	}
	return db, pool, actor
}

func testDBActorMonitor(t *testing.T, parent context.Context, db *gorm.DB, actor models.User, queryTimeout time.Duration) (*dbActorMonitor, chan<- time.Time, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	sessionCtx, revoke := context.WithCancel(parent)
	t.Cleanup(revoke)
	monitor := &dbActorMonitor{cancel: cancel, done: make(chan struct{})}
	ticks := make(chan time.Time, 1)
	go func() {
		defer close(monitor.done)
		monitor.run(ctx, db, actor.ID, ticks, queryTimeout, revoke)
	}()
	t.Cleanup(monitor.stop)
	return monitor, ticks, sessionCtx
}

func awaitActorMonitor(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("actor monitor did not finish promptly")
	}
}

func TestDBActorMonitorHealthyPolling(t *testing.T) {
	db, _, actor := actorMonitorFixture(t)
	queries := make(chan context.Context, 2)
	if err := db.Callback().Query().After("gorm:query").Register("test:actor_monitor_queries", func(tx *gorm.DB) {
		queries <- tx.Statement.Context
	}); err != nil {
		t.Fatal(err)
	}
	monitor, ticks, sessionCtx := testDBActorMonitor(t, context.Background(), db, actor, time.Second)
	for range 2 {
		ticks <- time.Now()
		select {
		case queryCtx := <-queries:
			if _, ok := queryCtx.Deadline(); !ok {
				t.Fatal("actor lookup has no deadline")
			}
			awaitActorMonitor(t, queryCtx.Done())
			if !errors.Is(queryCtx.Err(), context.Canceled) {
				t.Fatalf("healthy lookup context = %v, want prompt cancellation after lookup", queryCtx.Err())
			}
		case <-time.After(2 * time.Second):
			t.Fatal("actor lookup did not run")
		}
	}
	if err := monitor.finish(sessionCtx, nil); err != nil {
		t.Fatalf("healthy database session failed: %v", err)
	}
	monitor.stop() // Teardown is safe from both the explicit and deferred path.
	if monitor.revoked.Load() || sessionCtx.Err() != nil {
		t.Fatal("healthy actor was revoked during polling or teardown")
	}
	connectorErr := errors.New("database connector failed")
	if err := monitor.finish(sessionCtx, connectorErr); !errors.Is(err, connectorErr) {
		t.Fatalf("connector failure was lost: %v", err)
	}
}

func TestDBActorMonitorRevokesInvalidActor(t *testing.T) {
	for _, change := range []string{"disabled", "system", "deleted", "missing"} {
		t.Run(change, func(t *testing.T) {
			db, _, actor := actorMonitorFixture(t)
			var err error
			switch change {
			case "disabled":
				err = db.Model(&actor).Update("enabled", false).Error
			case "system":
				err = db.Model(&actor).Update("system_user", true).Error
			case "deleted":
				err = db.Model(&actor).Update("deleted_at", time.Now()).Error
			case "missing":
				err = db.Exec("DELETE FROM users WHERE id = ?", actor.ID).Error
			}
			if err != nil {
				t.Fatal(err)
			}
			monitor, ticks, sessionCtx := testDBActorMonitor(t, context.Background(), db, actor, time.Second)
			ticks <- time.Now()
			awaitActorMonitor(t, monitor.done)
			if !monitor.revoked.Load() || !errors.Is(sessionCtx.Err(), context.Canceled) {
				t.Fatal("invalid actor did not cancel the database session")
			}
			if err := monitor.finish(sessionCtx, nil); !errors.Is(err, errDBActorRevoked) {
				t.Fatalf("connector success bypassed actor revocation: %v", err)
			}
		})
	}
}

func TestDBActorMonitorQueryFailureRevokesSession(t *testing.T) {
	db, pool, actor := actorMonitorFixture(t)
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	monitor, ticks, sessionCtx := testDBActorMonitor(t, context.Background(), db, actor, time.Second)
	ticks <- time.Now()
	awaitActorMonitor(t, monitor.done)
	if !monitor.revoked.Load() || !errors.Is(sessionCtx.Err(), context.Canceled) {
		t.Fatal("failed actor lookup did not cancel the database session")
	}
	if err := monitor.finish(sessionCtx, nil); !errors.Is(err, errDBActorRevoked) {
		t.Fatalf("connector success bypassed failed actor lookup: %v", err)
	}
}

func holdActorMonitorConnection(t *testing.T, pool *sql.DB) *sql.Conn {
	t.Helper()
	conn, err := pool.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func awaitActorMonitorQueryWait(t *testing.T, pool *sql.DB) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for pool.Stats().WaitCount == 0 {
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("actor lookup did not wait for a database connection")
		}
	}
}

func TestDBActorMonitorQueryTimeoutRevokesSession(t *testing.T) {
	db, pool, actor := actorMonitorFixture(t)
	held := holdActorMonitorConnection(t, pool)
	monitor, ticks, sessionCtx := testDBActorMonitor(t, context.Background(), db, actor, 75*time.Millisecond)
	// Release the fixture before joining during failure cleanup, so a broken
	// cancellation implementation fails the test instead of hanging cleanup.
	t.Cleanup(func() { _ = held.Close() })
	ticks <- time.Now()
	awaitActorMonitorQueryWait(t, pool)
	awaitActorMonitor(t, monitor.done)
	if !monitor.revoked.Load() || !errors.Is(sessionCtx.Err(), context.Canceled) {
		t.Fatal("stalled actor lookup did not cancel the database session at its deadline")
	}
	if err := monitor.finish(sessionCtx, nil); !errors.Is(err, errDBActorRevoked) {
		t.Fatalf("connector success bypassed actor lookup timeout: %v", err)
	}
}

func TestDBActorMonitorLateSuccessfulQueryCannotBypassDeadline(t *testing.T) {
	db, _, actor := actorMonitorFixture(t)
	completed := make(chan error, 1)
	release := make(chan struct{})
	if err := db.Callback().Query().After("gorm:query").Register("test:actor_monitor_late_query", func(tx *gorm.DB) {
		fresh, ok := tx.Statement.Dest.(*models.User)
		if !ok || fresh.ID != actor.ID || !fresh.Enabled {
			t.Error("late query did not first load the healthy actor")
		}
		select {
		case <-tx.Statement.Context.Done():
		case <-release:
		}
		// Leave the successful query result intact after its deadline. The
		// monitor must check the context even though GORM reports no error.
		completed <- tx.Error
	}); err != nil {
		t.Fatal(err)
	}
	monitor, ticks, sessionCtx := testDBActorMonitor(t, context.Background(), db, actor, 75*time.Millisecond)
	t.Cleanup(func() { close(release) })
	ticks <- time.Now()
	awaitActorMonitor(t, monitor.done)
	select {
	case err := <-completed:
		if err != nil {
			t.Fatalf("late query returned an error instead of the intended successful result: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("monitor returned before the late query completed")
	}
	if !errors.Is(sessionCtx.Err(), context.Canceled) {
		t.Fatal("late successful query did not cancel the database session")
	}
	if err := monitor.finish(sessionCtx, nil); !errors.Is(err, errDBActorRevoked) {
		t.Fatalf("late query or connector success bypassed actor lookup deadline: %v", err)
	}
}

func TestDBActorMonitorCancellationInterruptsPendingQuery(t *testing.T) {
	for _, action := range []string{"parent cancellation", "stop"} {
		t.Run(action, func(t *testing.T) {
			db, pool, actor := actorMonitorFixture(t)
			held := holdActorMonitorConnection(t, pool)
			parent, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			monitor, ticks, _ := testDBActorMonitor(t, parent, db, actor, time.Minute)
			t.Cleanup(func() { _ = held.Close() })
			var completed atomic.Bool
			if err := db.Callback().Query().After("gorm:query").Register("test:actor_monitor_query_complete", func(tx *gorm.DB) {
				completed.Store(true)
			}); err != nil {
				t.Fatal(err)
			}
			ticks <- time.Now()
			awaitActorMonitorQueryWait(t, pool)
			if action == "parent cancellation" {
				cancel()
			} else {
				stopped := make(chan struct{})
				go func() {
					monitor.stop()
					close(stopped)
				}()
				awaitActorMonitor(t, stopped)
			}
			awaitActorMonitor(t, monitor.done)
			if !completed.Load() {
				t.Fatal("monitor returned before its pending query completed")
			}
			if monitor.revoked.Load() {
				t.Fatal("normal cancellation was audited as actor revocation")
			}
			finalErr := monitor.finish(parent, nil)
			if action == "parent cancellation" && !errors.Is(finalErr, context.Canceled) {
				t.Fatalf("connector success bypassed parent cancellation: %v", finalErr)
			}
			if action == "stop" && finalErr != nil {
				t.Fatalf("healthy monitor teardown failed the database session: %v", finalErr)
			}
			if got := pool.Stats().InUse; got != 1 {
				t.Fatalf("database connections in use = %d, want only the held fixture connection", got)
			}
		})
	}
}

func TestDBActorMonitorCanceledParentStopsWorker(t *testing.T) {
	db, _, actor := actorMonitorFixture(t)
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	monitor := startDBActorMonitor(parent, db, actor.ID, func() {
		t.Error("already canceled session was revoked")
	})
	awaitActorMonitor(t, monitor.done)
	monitor.stop()
}
