package secretstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"goBastion/internal/utils/cryptokey"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// These checks are opt-in and create only fresh, random schemas in the supplied
// database. They never clear an existing schema or table.
func postgresIntegrationDB(t *testing.T, seed bool) (*gorm.DB, string, string) {
	t.Helper()
	dsn := os.Getenv("GOB_SECRET_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set GOB_SECRET_POSTGRES_DSN to run PostgreSQL secret migration checks")
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	schema := "gob_secretstore_" + hex.EncodeToString(random)
	database := openPostgresIntegrationConnection(t, dsn, "")
	if err := database.Exec(`CREATE SCHEMA "` + schema + `"`).Error; err != nil {
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	t.Cleanup(func() {
		// schema contains only our fixed prefix and random hexadecimal bytes.
		if err := database.Exec(`SET search_path TO public`).Error; err != nil {
			t.Errorf("reset integration search_path: %v", err)
		}
		if err := database.Exec(`DROP SCHEMA "` + schema + `" CASCADE`).Error; err != nil {
			t.Errorf("remove generated integration schema: %v", err)
		}
	})
	if err := database.Exec(`SET search_path TO "` + schema + `"`).Error; err != nil {
		t.Fatal(err)
	}
	for _, c := range fixtureColumns {
		valueType := "TEXT"
		if c.binary {
			valueType = "BYTEA"
		}
		query := fmt.Sprintf("CREATE TABLE %s (%s TEXT PRIMARY KEY, %s %s, deleted_at TIMESTAMPTZ)", c.table, c.primary, c.secret, valueType)
		if err := database.Exec(query).Error; err != nil {
			t.Fatal(err)
		}
		if !seed {
			continue
		}
		for _, id := range []string{"active", "deleted"} {
			var value any = fixturePlaintext(c.table, id)
			if c.binary {
				value = []byte(fixturePlaintext(c.table, id))
			}
			var deleted any
			if id == "deleted" {
				deleted = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			query = fmt.Sprintf("INSERT INTO %s (%s,%s,deleted_at) VALUES (?,?,?)", c.table, c.primary, c.secret)
			if err := database.Exec(query, id, value, deleted).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	return database, dsn, schema
}

func openPostgresIntegrationConnection(t *testing.T, dsn, schema string) *gorm.DB {
	t.Helper()
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect PostgreSQL integration database: %v", err)
	}
	connection, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	// SET search_path is connection-local. Pin all work to one session instead
	// of allowing a pool to accidentally query a different schema.
	connection.SetMaxOpenConns(1)
	connection.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = connection.Close() })
	if schema != "" {
		if err := database.Exec(`SET search_path TO "` + schema + `"`).Error; err != nil {
			t.Fatal(err)
		}
	}
	return database
}

func TestPostgresMigrationDryRunApplyAndIdempotence(t *testing.T) {
	database, _, _ := postgresIntegrationDB(t, true)
	before := snapshotSecrets(t, database)
	if len(before) != 14 {
		t.Fatal("PostgreSQL fixture does not cover every secret family and tombstone")
	}
	if _, err := Migrate(database, Options{Apply: true}); err == nil {
		t.Fatal("PostgreSQL accepted plaintext without explicit authorization")
	}
	assertSnapshot(t, database, before)
	result, err := Migrate(database, Options{AllowPlaintext: true})
	if err != nil || result.Checked != 14 || result.Changed != 14 || result.Applied {
		t.Fatalf("PostgreSQL dry run failed: %+v, %v", result, err)
	}
	assertSnapshot(t, database, before)
	result, err = Migrate(database, Options{Apply: true, AllowPlaintext: true})
	if err != nil || result.Checked != 14 || result.Changed != 14 || !result.Applied {
		t.Fatalf("PostgreSQL apply failed: %+v, %v", result, err)
	}
	encrypted := snapshotSecrets(t, database)
	for name, raw := range encrypted {
		plaintext, err := cryptokey.Decrypt(raw)
		if err != nil || plaintext != before[name] || cryptokey.NeedsRotation(raw) {
			t.Fatalf("PostgreSQL row %s did not migrate correctly", name)
		}
	}
	var hostType string
	if err := database.Raw("SELECT pg_typeof(private_key)::text FROM ssh_host_keys LIMIT 1").Scan(&hostType).Error; err != nil || hostType != "bytea" {
		t.Fatal("PostgreSQL host keys did not preserve BYTEA storage")
	}
	for _, c := range fixtureColumns {
		var tombstones int64
		if err := database.Table(c.table).Where("deleted_at IS NOT NULL").Count(&tombstones).Error; err != nil || tombstones != 1 {
			t.Fatalf("PostgreSQL tombstone changed in %s", c.table)
		}
	}
	if err := ValidateStored(database); err != nil {
		t.Fatal(err)
	}
	result, err = Migrate(database, Options{Apply: true})
	if err != nil || result.Changed != 0 || !result.Applied {
		t.Fatalf("PostgreSQL second apply was not idempotent: %+v, %v", result, err)
	}
	assertSnapshot(t, database, encrypted)
}

// A physical/snapshot recovery preserves ciphertext bytes. Moving all seven
// secret columns to a new schema verifies that no connection-local state or
// migration metadata is needed to authenticate the restored data.
func TestPostgresEncryptedSnapshotRestoresIntoFreshSchema(t *testing.T) {
	source, _, _ := postgresIntegrationDB(t, true)
	if _, err := Migrate(source, Options{Apply: true, AllowPlaintext: true}); err != nil {
		t.Fatal(err)
	}
	encrypted := snapshotSecrets(t, source)
	restored, _, _ := postgresIntegrationDB(t, false)
	for _, c := range fixtureColumns {
		for _, id := range []string{"active", "deleted"} {
			var value any = encrypted[c.table+"/"+id]
			if c.binary {
				value = []byte(encrypted[c.table+"/"+id])
			}
			var deleted any
			if id == "deleted" {
				deleted = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			query := fmt.Sprintf("INSERT INTO %s (%s,%s,deleted_at) VALUES (?,?,?)", c.table, c.primary, c.secret)
			if err := restored.Exec(query, id, value, deleted).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := ValidateStored(restored); err != nil {
		t.Fatalf("restored PostgreSQL ciphertext was unreadable: %v", err)
	}
	result, err := Migrate(restored, Options{Apply: true})
	if err != nil || result.Checked != 14 || result.Changed != 0 || !result.Applied {
		t.Fatalf("restored PostgreSQL data required unexpected rewrites: %+v, %v", result, err)
	}
	assertSnapshot(t, restored, encrypted)
}

func TestPostgresMigrationCorruptLateRowRollsBackAllTables(t *testing.T) {
	for _, invalid := range []string{"gob:v2:active:corrupt-sensitive-secret", "gob:v99:active:unsupported-sensitive-secret"} {
		t.Run(strings.Split(invalid, ":")[1], func(t *testing.T) {
			database, _, _ := postgresIntegrationDB(t, true)
			// The users table is last, after writes to six other tables.
			setFixtureSecret(t, database, "users", "deleted", invalid)
			before := snapshotSecrets(t, database)
			result, err := Migrate(database, Options{Apply: true, AllowPlaintext: true})
			if err == nil || result.Changed != 0 || result.Applied {
				t.Fatal("PostgreSQL corrupt ciphertext did not abort the whole migration")
			}
			if strings.Contains(err.Error(), "sensitive-secret") {
				t.Fatal("PostgreSQL migration exposed a secret in its error")
			}
			assertSnapshot(t, database, before)
		})
	}
}

func TestPostgresConcurrentMigrationsSerializeOnRowLocks(t *testing.T) {
	database, dsn, schema := postgresIntegrationDB(t, true)
	competitor := openPostgresIntegrationConnection(t, dsn, schema)
	observer := openPostgresIntegrationConnection(t, dsn, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var competitorPID int
	if err := competitor.Raw("SELECT pg_backend_pid()").Scan(&competitorPID).Error; err != nil {
		t.Fatal(err)
	}
	lockHeld := make(chan struct{})
	release := make(chan struct{})
	var signalOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	if err := database.Callback().Query().After("gorm:query").Register("integration:hold_first_secret_lock", func(tx *gorm.DB) {
		if tx.Statement.Table != "group_db_accesses" || tx.Error != nil {
			return
		}
		signalOnce.Do(func() {
			close(lockHeld)
			select {
			case <-release:
			case <-ctx.Done():
			}
		})
	}); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result Result
		err    error
	}
	first := make(chan outcome, 1)
	second := make(chan outcome, 1)
	go func() {
		result, err := Migrate(database.WithContext(ctx), Options{Apply: true, AllowPlaintext: true})
		first <- outcome{result, err}
	}()
	select {
	case <-lockHeld:
	case <-ctx.Done():
		t.Fatal("first PostgreSQL migration did not acquire its row lock")
	}
	go func() {
		result, err := Migrate(competitor.WithContext(ctx), Options{Apply: true, AllowPlaintext: true})
		second <- outcome{result, err}
	}()
	// Observe an actual database lock wait instead of relying on elapsed time to
	// infer that the second transaction was blocked.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	blocked := false
	for !blocked {
		var blockers int
		if err := observer.WithContext(ctx).Raw("SELECT cardinality(pg_blocking_pids(?))", competitorPID).Scan(&blockers).Error; err != nil {
			t.Fatal(err)
		}
		blocked = blockers > 0
		if blocked {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("competing PostgreSQL migration did not wait on the row lock")
		}
	}
	unblock()
	for index, channel := range []chan outcome{first, second} {
		select {
		case got := <-channel:
			wantChanges := 14
			if index == 1 {
				wantChanges = 0
			}
			if got.err != nil || got.result.Changed != wantChanges || !got.result.Applied {
				t.Fatalf("concurrent PostgreSQL migration %d failed: %+v, %v", index, got.result, got.err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent PostgreSQL migrations did not finish")
		}
	}
	if err := ValidateStored(database); err != nil {
		t.Fatal(err)
	}
}
