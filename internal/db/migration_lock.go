package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"
)

// postgresMigrationLockKey is the database-scoped goBastion startup migration
// namespace (ASCII "goBastio"). Every migrating instance must use this key.
const postgresMigrationLockKey int64 = 0x676f42617374696f

const (
	migrationLockTimeout    = time.Minute
	migrationWorkTimeout    = 5 * time.Minute
	migrationUnlockTimeout  = 5 * time.Second
	migrationLockRetryDelay = 100 * time.Millisecond
)

func startupMigrate(ctx context.Context, db *gorm.DB, dialect string, log *slog.Logger) error {
	work := func(txDB *gorm.DB) error {
		if err := migrate(txDB, dialect); err != nil {
			return err
		}
		if dialect == "postgres" {
			return fixPostgresBoolColumns(txDB)
		}
		return nil
	}
	if dialect == "postgres" {
		return withPostgresMigrationLock(ctx, db, log, work)
	}
	// SQLite retains its standalone migration behavior. MySQL has no migration
	// coordinator here; PostgreSQL advisory-lock guarantees do not apply to it.
	return work(db)
}

// withPostgresMigrationLock executes work on the same physical connection that
// owns the session advisory lock. work must finish all use of txDB before it
// returns and must finish any transactions it starts (gorm.Transaction does so).
// Acquisition, migration SQL and cleanup have separate bounded contexts.
func withPostgresMigrationLock(ctx context.Context, db *gorm.DB, log *slog.Logger, work func(txDB *gorm.DB) error) (err error) {
	started := time.Now()
	acquireCtx, cancelAcquire := context.WithTimeout(ctx, migrationLockTimeout)
	defer cancelAcquire()
	pool, err := db.DB()
	if err != nil {
		return fmt.Errorf("get migration connection pool: %w", err)
	}
	conn, err := pool.Conn(acquireCtx)
	if err != nil {
		return fmt.Errorf("pin migration connection: %w", err)
	}
	held, uncertain := false, false
	defer func() {
		if held {
			// Cancellation of startup must not cancel the attempt to unlock.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), migrationUnlockTimeout)
			var unlocked bool
			unlockErr := conn.QueryRowContext(cleanupCtx, "SELECT pg_advisory_unlock($1)", postgresMigrationLockKey).Scan(&unlocked)
			cancel()
			if unlockErr != nil || !unlocked {
				uncertain = true
				if unlockErr == nil {
					unlockErr = errors.New("migration advisory lock was not held")
				}
				err = errors.Join(err, fmt.Errorf("release PostgreSQL migration lock: %w", unlockErr))
				if log != nil {
					log.Error("db_migration_unlock_failed")
				}
			}
		}
		if uncertain {
			// Close alone returns a healthy connection to the pool. ErrBadConn
			// forces database/sql to close it, dropping any server-side lock.
			discardErr := conn.Raw(func(any) error { return driver.ErrBadConn })
			if discardErr != nil && !errors.Is(discardErr, driver.ErrBadConn) && !errors.Is(discardErr, sql.ErrConnDone) {
				err = errors.Join(err, fmt.Errorf("discard migration connection: %w", discardErr))
			}
		}
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, sql.ErrConnDone) {
			err = errors.Join(err, fmt.Errorf("close migration connection: %w", closeErr))
		}
	}()

	for {
		if err = acquireCtx.Err(); err != nil {
			break
		}
		err = conn.QueryRowContext(acquireCtx, "SELECT pg_try_advisory_lock($1)", postgresMigrationLockKey).Scan(&held)
		if err != nil {
			// A lost/canceled reply may still mean the server acquired the lock.
			uncertain = true
			break
		}
		if held {
			break
		}
		timer := time.NewTimer(migrationLockRetryDelay)
		select {
		case <-acquireCtx.Done():
			timer.Stop()
			err = acquireCtx.Err()
		case <-timer.C:
		}
		if err != nil {
			break
		}
	}
	if log != nil {
		log.Info("db_migration_lock", slog.Duration("wait", time.Since(started)), slog.Bool("acquired", held))
	}
	if err != nil {
		return fmt.Errorf("acquire PostgreSQL migration lock: %w", err)
	}
	cancelAcquire()
	workCtx, cancelWork := context.WithTimeout(ctx, migrationWorkTimeout)
	defer cancelWork()
	if err := workCtx.Err(); err != nil {
		return err
	}
	// Session(Context) clones the Statement; never mutate the parent's pool.
	txDB := db.Session(&gorm.Session{NewDB: true, Context: workCtx})
	txDB.ConnPool = conn
	txDB.Statement.ConnPool = conn
	if err := work(txDB); err != nil {
		return err
	}
	return workCtx.Err()
}
