package db

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite memory db: %v", err)
	}

	if err := db.AutoMigrate(ManagedModelsInDependencyOrder()...); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	return db
}

func TestExportRequiresKey(t *testing.T) {
	t.Setenv("DB_EXPORT_KEY", "")

	db := openTestDB(t)
	var buf bytes.Buffer

	err := Export(db, &buf, nil)
	if err == nil {
		t.Fatalf("expected error when DB_EXPORT_KEY is missing")
	}
	if !strings.Contains(err.Error(), "DB_EXPORT_KEY must be set") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportProducesEnvelope(t *testing.T) {
	t.Setenv("DB_EXPORT_KEY", "0123456789abcdef0123456789abcdef")

	db := openTestDB(t)
	var buf bytes.Buffer

	if err := Export(db, &buf, nil); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	var env exportEnvelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("invalid export envelope json: %v", err)
	}

	if env.Format != exportFormatName {
		t.Fatalf("unexpected format: %q", env.Format)
	}
	if env.Version != exportFormatVersion {
		t.Fatalf("unexpected version: %d", env.Version)
	}
	if env.Nonce == "" {
		t.Fatalf("nonce should not be empty")
	}
	if env.Payload == "" {
		t.Fatalf("payload should not be empty")
	}
}

func TestImportRejectsEmptyInput(t *testing.T) {
	t.Setenv("DB_EXPORT_KEY", "0123456789abcdef0123456789abcdef")

	db := openTestDB(t)

	err := Import(db, bytes.NewBuffer(nil), nil)
	if err == nil {
		t.Fatalf("expected error on empty input")
	}
	if !strings.Contains(err.Error(), "empty import input") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTryDirectAESKey(t *testing.T) {
	key, ok := tryDirectAESKey("0123456789abcdef")
	if !ok {
		t.Fatalf("expected direct raw AES key to be accepted")
	}
	if len(key) != 16 {
		t.Fatalf("unexpected key length: %d", len(key))
	}
}

func TestDeriveKeyForExportWithPassphrase(t *testing.T) {
	key, kdf, err := deriveKeyForExport("my-passphrase")
	if err != nil {
		t.Fatalf("deriveKeyForExport failed: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("unexpected derived key length: %d", len(key))
	}
	if kdf.Name != "argon2id" {
		t.Fatalf("unexpected kdf: %q", kdf.Name)
	}
	if kdf.Salt == "" {
		t.Fatalf("argon2id salt should not be empty")
	}
}

func TestDeriveKeyForImportRejectsExcessiveArgon2Parameters(t *testing.T) {
	kdf := exportKDFEnvelope{
		Name: "argon2id", Salt: "MDEyMzQ1Njc4OWFiY2RlZg==",
		Time: 1, Memory: maxArgon2Memory + 1, Threads: 1, KeyLen: 32,
	}
	if _, err := deriveKeyForImport("secret", kdf); err == nil {
		t.Fatal("expected excessive Argon2 memory to be rejected")
	}
}

func TestValidateImportTablesRejectsMissingAndDuplicateTables(t *testing.T) {
	db := openTestDB(t)
	if err := validateImportTables(db, nil); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected missing-table error, got %v", err)
	}
	sch, err := parseModelSchema(db, ManagedModelsInDependencyOrder()[0])
	if err != nil {
		t.Fatal(err)
	}
	tables := make([]exportTable, 0, len(ManagedModelsInDependencyOrder())+1)
	for _, model := range ManagedModelsInDependencyOrder() {
		modelSchema, parseErr := parseModelSchema(db, model)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		tables = append(tables, exportTable{Name: modelSchema.Table})
	}
	tables = append(tables, exportTable{Name: sch.Table})
	if err := validateImportTables(db, tables); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-table error, got %v", err)
	}
}

func TestMain(m *testing.M) {
	// Avoid accidental leakage from caller environment
	_ = os.Unsetenv("DB_EXPORT_KEY")
	os.Exit(m.Run())
}

func TestEncodeCellZeroTimeIsNull(t *testing.T) {
	field := &schema.Field{FieldType: reflect.TypeOf(time.Time{}), Name: "LastConnection"}
	cell, err := encodeCell(field, time.Time{})
	if err != nil {
		t.Fatalf("encodeCell(zero time): %v", err)
	}
	if cell.Type != "null" {
		t.Fatalf("expected zero time to encode as null, got type=%q value=%v", cell.Type, cell.Value)
	}
}

func TestQuoteIdentReservedWords(t *testing.T) {
	// MySQL reserved words in column names (e.g. ingress_keys.key) must be quoted.
	if got := quoteIdent("key", "mysql"); got != "`key`" {
		t.Fatalf("mysql quoteIdent(key)=%q, want `key`", got)
	}
	if got := quoteIdent("type", "mysql"); got != "`type`" {
		t.Fatalf("mysql quoteIdent(type)=%q, want `type`", got)
	}
	if got := quoteIdent("key", "postgres"); got != `"key"` {
		t.Fatalf("postgres quoteIdent(key)=%q, want \"key\"", got)
	}
	if got := quoteIdent("key", "sqlite"); got != `"key"` {
		t.Fatalf("sqlite quoteIdent(key)=%q, want \"key\"", got)
	}
}
