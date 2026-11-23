package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"goBastion/internal/models"
)

// This test requires a disposable database. PostgreSQL snapshot visibility is
// observed through another connection belonging to the same database role.
// MySQL is checked through concurrent writes and the exported old snapshot.
// Do not use a deployment DSN.
func TestBackendExportSnapshotLifecycle(t *testing.T) {
	driver := os.Getenv("GOB_EXPORT_LIFECYCLE_DRIVER")
	dsn := os.Getenv("GOB_EXPORT_LIFECYCLE_DSN")
	if driver == "" || dsn == "" {
		t.Skip("disposable export-lifecycle backend is not configured")
	}
	if driver != "mysql" && driver != "postgres" {
		t.Fatal("GOB_EXPORT_LIFECYCLE_DRIVER must be mysql or postgres")
	}
	t.Setenv("DB_EXPORT_KEY", lifecycleExportKey)
	for _, outcome := range []string{"commit", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			open := func() (*gorm.DB, *sql.DB) {
				var dialect gorm.Dialector
				if driver == "postgres" {
					dialect = postgres.Open(dsn)
				} else {
					dialect = mysql.Open(dsn)
				}
				db, err := gorm.Open(dialect, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
				if err != nil {
					t.Fatalf("open disposable %s database failed (%T)", driver, err)
				}
				pool, err := db.DB()
				if err != nil {
					t.Fatal(err)
				}
				pool.SetMaxOpenConns(1)
				pool.SetMaxIdleConns(1)
				t.Cleanup(func() { _ = pool.Close() })
				return db, pool
			}
			source, pool := open()
			if err := source.AutoMigrate(ManagedModelsInDependencyOrder()...); err != nil {
				t.Fatalf("migrate disposable %s fixture: %v", driver, err)
			}
			writer, _ := open()
			fixture := models.BastionInstance{InstanceID: "export-lifecycle-" + uuid.NewString(), Config: "before"}
			if err := source.Create(&fixture).Error; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = writer.Unscoped().Delete(&fixture).Error })
			var backendID int64
			if driver == "postgres" {
				if err := source.Raw("SELECT pg_backend_pid()").Scan(&backendID).Error; err != nil {
					t.Fatal(err)
				}
				if count := backendExportSnapshots(t, writer, backendID); count != 0 {
					t.Fatalf("backend connection already has %d observed snapshots before export", count)
				}
			}
			ready, release := pauseExportSnapshot(t, source)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var dump bytes.Buffer
			done := make(chan error, 1)
			go func() { done <- Export(source.WithContext(ctx), &dump, nil) }()
			awaitExportLifecycle(t, ready)
			if stats := pool.Stats(); stats.InUse != 1 {
				t.Fatalf("snapshot did not retain exactly one backend connection: %+v", stats)
			}
			if driver == "postgres" {
				if count := backendExportSnapshots(t, writer, backendID); count != 1 {
					t.Fatal("held export snapshot was not visible to PostgreSQL backend observer")
				}
			}
			writeCtx, writeCancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer writeCancel()
			for update := range 8 {
				value := fmt.Sprintf("%d:%s", update, strings.Repeat("x", 16*1024))
				if err := writer.WithContext(writeCtx).Model(&fixture).Update("config", value).Error; err != nil {
					t.Fatalf("concurrent %s writer blocked by snapshot: %v", driver, err)
				}
			}
			if result := writer.WithContext(writeCtx).Delete(&fixture); result.Error != nil || result.RowsAffected != 1 {
				t.Fatalf("concurrent %s delete failed: rows=%d error=%v", driver, result.RowsAffected, result.Error)
			}
			t.Logf("%s held export connection allowed 8 concurrent updates and a delete", driver)
			if outcome == "cancel" {
				cancel()
			} else {
				release()
			}
			err := finishExportLifecycle(t, done)
			if outcome == "cancel" {
				if !errors.Is(err, context.Canceled) || dump.Len() != 0 {
					t.Fatalf("canceled %s export returned error=%v output=%d bytes", driver, err, dump.Len())
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertLifecycleSnapshotConfig(t, dump.Bytes(), fixture.InstanceID, "before")
			}
			assertExportPoolReleased(t, pool)
			if driver == "postgres" {
				deadline := time.Now().Add(2 * time.Second)
				for backendExportSnapshots(t, writer, backendID) != 0 {
					if time.Now().After(deadline) {
						t.Fatal("finished export retained its PostgreSQL backend snapshot")
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		})
	}
}

func backendExportSnapshots(t *testing.T, observer *gorm.DB, backendID int64) int64 {
	t.Helper()
	var count int64
	query := "SELECT count(*) FROM pg_stat_activity WHERE pid = ? AND backend_xmin IS NOT NULL AND xact_start IS NOT NULL"
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := observer.WithContext(ctx).Raw(query, backendID).Scan(&count).Error; err != nil {
		t.Fatalf("observe PostgreSQL export snapshot: %v", err)
	}
	return count
}
