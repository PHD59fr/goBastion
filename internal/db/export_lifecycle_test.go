package db

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"goBastion/internal/models"
)

const lifecycleExportKey = "0123456789abcdef0123456789abcdef"

func openSQLiteExportLifecycle(t *testing.T) (*gorm.DB, *gorm.DB, *sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "export.db")
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(100)&_pragma=foreign_keys(1)&_pragma=wal_autocheckpoint(0)"
	open := func() (*gorm.DB, *sql.DB) {
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatal(err)
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
		t.Fatal(err)
	}
	writer, _ := open()
	return source, writer, pool, path
}

// Export reads users before groups. Pausing at the next row query holds a real
// snapshot after earlier tables have been consumed, without keeping a sql.Rows
// open or relying on a query callback that Rows does not execute.
func pauseExportSnapshot(t *testing.T, source *gorm.DB) (<-chan struct{}, func()) {
	t.Helper()
	ready, release := make(chan struct{}), make(chan struct{})
	var entered, released sync.Once
	if err := source.Callback().Row().Before("gorm:row").Register("test:pause_export_snapshot", func(tx *gorm.DB) {
		if tx.Statement.Table != "groups" {
			return
		}
		entered.Do(func() {
			close(ready)
			select {
			case <-release:
			case <-tx.Statement.Context.Done():
			}
		})
	}); err != nil {
		t.Fatal(err)
	}
	unblock := func() { released.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	return ready, unblock
}

func awaitExportLifecycle(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("export did not reach the held snapshot")
	}
}

func finishExportLifecycle(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("export did not release its snapshot")
		return nil
	}
}

func assertExportPoolReleased(t *testing.T, pool *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := pool.PingContext(ctx); err != nil {
		t.Fatalf("export connection was not returned to the single-connection pool: %v", err)
	}
	if stats := pool.Stats(); stats.InUse != 0 {
		t.Fatalf("connections still in use after export: %+v", stats)
	}
}

func sqliteCheckpoint(t *testing.T, db *gorm.DB) (busy, frames, checkpointed int) {
	t.Helper()
	if err := db.Raw("PRAGMA wal_checkpoint(TRUNCATE)").Row().Scan(&busy, &frames, &checkpointed); err != nil {
		t.Fatal(err)
	}
	return
}

func decodeLifecycleExport(t *testing.T, dump []byte) exportPayload {
	t.Helper()
	var envelope exportEnvelope
	if err := json.Unmarshal(dump, &envelope); err != nil {
		t.Fatal(err)
	}
	key, err := deriveKeyForImport(lifecycleExportKey, envelope.KDF)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptAESGCM(key, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var payload exportPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertLifecycleSnapshotConfig(t *testing.T, dump []byte, instance, want string) {
	t.Helper()
	for _, table := range decodeLifecycleExport(t, dump).Tables {
		if table.Name != "bastion_instances" {
			continue
		}
		for _, row := range table.Rows {
			if row["instance_id"].Value == instance {
				if got := row["config"].Value; got != want {
					t.Fatalf("snapshot config = %v, want %q", got, want)
				}
				return
			}
		}
	}
	t.Fatal("export lost the lifecycle fixture")
}

func TestSQLiteExportSnapshotRetainsWALUntilReleased(t *testing.T) {
	t.Setenv("DB_EXPORT_KEY", lifecycleExportKey)
	for _, outcome := range []string{"commit", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			source, writer, pool, path := openSQLiteExportLifecycle(t)
			fixture := models.BastionInstance{InstanceID: "long-export", Config: "before"}
			if err := source.Create(&fixture).Error; err != nil {
				t.Fatal(err)
			}
			if busy, _, _ := sqliteCheckpoint(t, writer); busy != 0 {
				t.Fatal("initial checkpoint was busy")
			}
			ready, release := pauseExportSnapshot(t, source)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var dump bytes.Buffer
			done := make(chan error, 1)
			go func() { done <- Export(source.WithContext(ctx), &dump, nil) }()
			awaitExportLifecycle(t, ready)
			if stats := pool.Stats(); stats.InUse != 1 {
				t.Fatalf("held snapshot did not retain exactly one connection: %+v", stats)
			}
			// Writers still commit in WAL mode, but the old reader prevents the
			// checkpoint from reclaiming frames accumulated during the export.
			for update := range 8 {
				value := fmt.Sprintf("%d:%s", update, strings.Repeat("x", 64*1024))
				if err := writer.Model(&fixture).Update("config", value).Error; err != nil {
					t.Fatalf("writer blocked by export snapshot: %v", err)
				}
			}
			if result := writer.Delete(&fixture); result.Error != nil || result.RowsAffected != 1 {
				t.Fatalf("concurrent delete failed: rows=%d error=%v", result.RowsAffected, result.Error)
			}
			busy, frames, checkpointed := sqliteCheckpoint(t, writer)
			if busy != 1 || frames <= checkpointed {
				t.Fatalf("long snapshot did not retain WAL frames: busy=%d frames=%d checkpointed=%d", busy, frames, checkpointed)
			}
			wal, err := os.Stat(path + "-wal")
			if err != nil || wal.Size() == 0 {
				t.Fatalf("WAL growth was not observed: %v", err)
			}
			t.Logf("held snapshot: WAL bytes=%d frames=%d checkpointed=%d; 8 updates and a delete committed", wal.Size(), frames, checkpointed)
			if outcome == "cancel" {
				cancel()
			} else {
				release()
			}
			err = finishExportLifecycle(t, done)
			if outcome == "cancel" {
				if !errors.Is(err, context.Canceled) || dump.Len() != 0 {
					t.Fatalf("canceled export returned error=%v output=%d bytes", err, dump.Len())
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertLifecycleSnapshotConfig(t, dump.Bytes(), fixture.InstanceID, "before")
			}
			assertExportPoolReleased(t, pool)
			if busy, frames, checkpointed := sqliteCheckpoint(t, writer); busy != 0 || frames != 0 || checkpointed != 0 {
				t.Fatalf("finished export retained WAL: busy=%d frames=%d checkpointed=%d", busy, frames, checkpointed)
			}
		})
	}
}

type heldExportOutput struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *heldExportOutput) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(data), nil
}

func TestExportReleasesSnapshotBeforeSlowOutput(t *testing.T) {
	t.Setenv("DB_EXPORT_KEY", lifecycleExportKey)
	source, _, pool, _ := openSQLiteExportLifecycle(t)
	output := &heldExportOutput{started: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(output.release) }) }
	defer unblock()
	done := make(chan error, 1)
	go func() { done <- Export(source, output, nil) }()
	awaitExportLifecycle(t, output.started)
	assertExportPoolReleased(t, pool)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := source.WithContext(ctx).Create(&models.BastionInstance{InstanceID: "while-output-blocked"}).Error; err != nil {
		t.Fatalf("slow output retained the snapshot or connection: %v", err)
	}
	unblock()
	if err := finishExportLifecycle(t, done); err != nil {
		t.Fatal(err)
	}
}

var _ io.Writer = (*heldExportOutput)(nil)
