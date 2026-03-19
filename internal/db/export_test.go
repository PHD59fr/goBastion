package db

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
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

func TestMain(m *testing.M) {
	// Avoid accidental leakage from caller environment
	_ = os.Unsetenv("DB_EXPORT_KEY")
	os.Exit(m.Run())
}
