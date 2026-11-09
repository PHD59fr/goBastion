package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

// This driver exercises uncertain server replies without depending on a live
// PostgreSQL server or adding a mocking dependency.
type migrationLockFixture struct {
	mu             sync.Mutex
	opened, closed int
	unlocks        int
	busy           bool
	acquireErr     error
	unlockErr      error
	unlockFalse    bool
	cleanupActive  bool
}

type migrationLockConnector struct{ fixture *migrationLockFixture }

func (c migrationLockConnector) Connect(context.Context) (driver.Conn, error) {
	c.fixture.mu.Lock()
	defer c.fixture.mu.Unlock()
	c.fixture.opened++
	return &migrationLockConn{fixture: c.fixture}, nil
}
func (c migrationLockConnector) Driver() driver.Driver { return migrationLockDriver{} }

type migrationLockDriver struct{}

func (migrationLockDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector required")
}

type migrationLockConn struct{ fixture *migrationLockFixture }

func (c *migrationLockConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *migrationLockConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c *migrationLockConn) Close() error {
	c.fixture.mu.Lock()
	defer c.fixture.mu.Unlock()
	c.fixture.closed++
	return nil
}
func (c *migrationLockConn) QueryContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.fixture.mu.Lock()
	defer c.fixture.mu.Unlock()
	switch {
	case strings.Contains(query, "pg_try_advisory_lock"):
		if c.fixture.acquireErr != nil {
			return nil, c.fixture.acquireErr
		}
		return &migrationLockRows{value: !c.fixture.busy}, nil
	case strings.Contains(query, "pg_advisory_unlock"):
		c.fixture.unlocks++
		c.fixture.cleanupActive = ctx.Err() == nil
		if c.fixture.unlockErr != nil {
			return nil, c.fixture.unlockErr
		}
		return &migrationLockRows{value: !c.fixture.unlockFalse}, nil
	default:
		return nil, errors.New("unexpected query")
	}
}

type migrationLockRows struct {
	value bool
	done  bool
}

func (*migrationLockRows) Columns() []string { return []string{"locked"} }
func (*migrationLockRows) Close() error      { return nil }
func (r *migrationLockRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	dest[0], r.done = r.value, true
	return nil
}

func migrationLockTestDB(t *testing.T, fixture *migrationLockFixture) (*gorm.DB, *sql.DB) {
	t.Helper()
	pool := sql.OpenDB(migrationLockConnector{fixture: fixture})
	t.Cleanup(func() { _ = pool.Close() })
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{
		DisableAutomaticPing: true,
		Logger:               gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	return db, pool
}

func TestMigrationLockCleanup(t *testing.T) {
	workError := errors.New("injected migration failure")
	for _, test := range []struct {
		name        string
		fixture     *migrationLockFixture
		workErr     error
		cancel      bool
		wantDiscard bool
		wantErr     bool
	}{
		{name: "success"},
		{name: "migration error", workErr: workError, wantErr: true},
		{name: "canceled work", cancel: true, wantErr: true},
		{name: "uncertain acquisition", fixture: &migrationLockFixture{acquireErr: io.ErrUnexpectedEOF}, wantDiscard: true, wantErr: true},
		{name: "uncertain unlock", fixture: &migrationLockFixture{unlockErr: io.ErrUnexpectedEOF}, wantDiscard: true, wantErr: true},
		{name: "missing lock", fixture: &migrationLockFixture{unlockFalse: true}, wantDiscard: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := test.fixture
			if fixture == nil {
				fixture = &migrationLockFixture{}
			}
			db, pool := migrationLockTestDB(t, fixture)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := false
			err := withPostgresMigrationLock(ctx, db, nil, func(txDB *gorm.DB) error {
				called = true
				if txDB.ConnPool == pool || txDB.Statement.ConnPool == pool || db.Statement.ConnPool != pool || db.ConnPool != pool {
					t.Fatal("migration must pin its clone without changing the original DB")
				}
				if _, ok := txDB.Statement.Context.Deadline(); !ok {
					t.Fatal("migration SQL has no deadline")
				}
				if test.cancel {
					cancel()
					return ctx.Err()
				}
				return test.workErr
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, want error %v", err, test.wantErr)
			}
			if test.workErr != nil && !errors.Is(err, test.workErr) {
				t.Fatalf("lost migration error: %v", err)
			}
			if fixture.acquireErr != nil && called {
				t.Fatal("migration ran after uncertain acquisition")
			}
			// A second checkout proves healthy sessions are reusable and uncertain
			// sessions were physically discarded instead of returned to the pool.
			conn, checkoutErr := pool.Conn(context.Background())
			if checkoutErr != nil {
				t.Fatal(checkoutErr)
			}
			_ = conn.Close()
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if test.wantDiscard {
				if fixture.opened != 2 || fixture.closed != 1 {
					t.Fatalf("uncertain connection reused: opened=%d closed=%d", fixture.opened, fixture.closed)
				}
			} else if fixture.opened != 1 || fixture.closed != 0 {
				t.Fatalf("healthy connection not reused: opened=%d closed=%d", fixture.opened, fixture.closed)
			}
			if called && (fixture.unlocks != 1 || !fixture.cleanupActive) {
				t.Fatalf("cleanup missing or canceled: unlocks=%d active=%v", fixture.unlocks, fixture.cleanupActive)
			}
		})
	}
}

func TestMigrationLockPanicReleases(t *testing.T) {
	fixture := &migrationLockFixture{}
	db, _ := migrationLockTestDB(t, fixture)
	func() {
		defer func() {
			if recovered := recover(); recovered != "migration panic" {
				t.Fatalf("panic not preserved: %v", recovered)
			}
		}()
		_ = withPostgresMigrationLock(context.Background(), db, nil, func(*gorm.DB) error { panic("migration panic") })
	}()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.unlocks != 1 || fixture.closed != 0 {
		t.Fatalf("panic cleanup: unlocks=%d closed=%d", fixture.unlocks, fixture.closed)
	}
}

func TestMigrationLockAcquisitionCancellation(t *testing.T) {
	fixture := &migrationLockFixture{busy: true}
	db, _ := migrationLockTestDB(t, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := withPostgresMigrationLock(ctx, db, nil, func(*gorm.DB) error {
		t.Fatal("migration ran without lock")
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected bounded acquisition failure, got %v", err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.unlocks != 0 {
		t.Fatal("waiter tried to unlock another session's lock")
	}
}

// PostgreSQL tests share the existing disposable-fixture DSN, but all DDL is in
// a fresh schema. Each participant has its own connection pool.
func postgresMigrationTestDB(t *testing.T) (*gorm.DB, func() *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("GOB_SECRET_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set GOB_SECRET_POSTGRES_DSN to a disposable PostgreSQL database")
	}
	pgConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid disposable PostgreSQL connection configuration")
	}
	open := func() *gorm.DB {
		pool := stdlib.OpenDB(*pgConfig.Copy())
		t.Cleanup(func() { _ = pool.Close() })
		db, openErr := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{Logger: gormLogger.Default.LogMode(gormLogger.Silent)})
		if openErr != nil {
			t.Fatal("cannot open disposable PostgreSQL database")
		}
		return db
	}
	admin := open()
	schema := fmt.Sprintf("migration_lock_%d", time.Now().UnixNano())
	if err := admin.Exec(`CREATE SCHEMA "` + schema + `"`).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Exec(`DROP SCHEMA "` + schema + `" CASCADE`).Error; err != nil {
			t.Error(err)
		}
	})
	pgConfig.RuntimeParams["search_path"] = schema
	return open(), open
}

func TestPostgresMigrationLockSerialization(t *testing.T) {
	first, open := postgresMigrationTestDB(t)
	second := open()
	entered, release, secondEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() {
		firstDone <- withPostgresMigrationLock(ctx, first, nil, func(txDB *gorm.DB) error {
			var before, after int
			if err := txDB.Raw("SELECT pg_backend_pid()").Scan(&before).Error; err != nil {
				return err
			}
			var ownsLock bool
			if err := txDB.Raw(`SELECT EXISTS (SELECT 1 FROM pg_locks
				WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted
				AND classid::bigint = ? AND objid::bigint = ? AND objsubid = 1)`,
				postgresMigrationLockKey>>32, postgresMigrationLockKey&0xffffffff).Scan(&ownsLock).Error; err != nil {
				return err
			}
			if !ownsLock {
				return errors.New("migration callback is not on the lock-owning PostgreSQL session")
			}
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			if err := migrate(txDB, "postgres"); err != nil {
				return err
			}
			if err := fixPostgresBoolColumns(txDB); err != nil {
				return err
			}
			if err := txDB.Raw("SELECT pg_backend_pid()").Scan(&after).Error; err != nil {
				return err
			}
			if before != after {
				return errors.New("migration changed PostgreSQL session")
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-firstDone:
		t.Fatalf("first migration did not enter: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		secondDone <- withPostgresMigrationLock(ctx, second, nil, func(txDB *gorm.DB) error {
			close(secondEntered)
			if err := migrate(txDB, "postgres"); err != nil {
				return err
			}
			return fixPostgresBoolColumns(txDB)
		})
	}()
	var earlySecondErr error
	secondReturned := false
	select {
	case <-secondEntered:
		t.Error("concurrent migration entered while first held the lock")
	case err := <-secondDone:
		t.Errorf("waiter returned while first held lock: %v", err)
		earlySecondErr, secondReturned = err, true
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if !secondReturned {
		earlySecondErr = <-secondDone
	}
	if earlySecondErr != nil {
		t.Fatal(earlySecondErr)
	}
}

func TestPostgresMigrationLockAcquisitionTimeout(t *testing.T) {
	db, open := postgresMigrationTestDB(t)
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	holder, err := pool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if _, err := holder.ExecContext(ctx, "SELECT pg_advisory_lock($1)", postgresMigrationLockKey); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancelWait := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancelWait()
	err = withPostgresMigrationLock(waitCtx, open(), nil, func(*gorm.DB) error {
		t.Error("waiter migrated despite timing out")
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected acquisition deadline, got %v", err)
	}
	var unlocked bool
	if err := holder.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", postgresMigrationLockKey).Scan(&unlocked); err != nil || !unlocked {
		t.Fatalf("waiter disturbed holder lock: unlocked=%v error=%v", unlocked, err)
	}
	if err := withPostgresMigrationLock(ctx, open(), nil, func(*gorm.DB) error { return nil }); err != nil {
		t.Fatalf("migration after holder release failed: %v", err)
	}
}

func TestPostgresMigrationLockErrorCancellationAndPanicRelease(t *testing.T) {
	db, open := postgresMigrationTestDB(t)
	for _, mode := range []string{"error", "cancellation", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			func() {
				defer func() {
					if recovered := recover(); recovered != nil && (mode != "panic" || recovered != "fixture panic") {
						t.Fatalf("unexpected panic: %v", recovered)
					}
				}()
				err := withPostgresMigrationLock(ctx, db, nil, func(txDB *gorm.DB) error {
					if err := txDB.Exec(`CREATE TABLE IF NOT EXISTS lock_release_fixture (id integer)`).Error; err != nil {
						return err
					}
					if mode == "panic" {
						panic("fixture panic")
					}
					if mode == "cancellation" {
						cancel()
						return ctx.Err()
					}
					return errors.New("fixture migration failure")
				})
				if err == nil {
					t.Fatal("expected migration failure")
				}
			}()
			nextCtx, nextCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer nextCancel()
			if err := withPostgresMigrationLock(nextCtx, open(), nil, func(*gorm.DB) error { return nil }); err != nil {
				t.Fatalf("next independent session could not acquire after %s: %v", mode, err)
			}
		})
	}
}
