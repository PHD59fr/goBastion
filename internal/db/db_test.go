package db

import (
	"os"
	"testing"
)

func TestInit_SQLite_InMemory(t *testing.T) {
	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DB_DSN", ":memory:")

	gormDB, err := Init(nil, true)
	if err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	sqlDB, err := gormDB.DB()
	if err != nil {
		t.Fatalf("gormDB.DB() error: %v", err)
	}
	if err = sqlDB.Ping(); err != nil {
		t.Fatalf("db ping failed: %v", err)
	}
}

func TestInit_SQLite_DefaultDriver(t *testing.T) {
	_ = os.Unsetenv("DB_DRIVER")
	// Use a temp dir so the test doesn't need /var/lib/goBastion.
	tmp := t.TempDir()
	dbPath := tmp + "/test.db"
	t.Setenv("DB_DSN", "file:"+dbPath+"?cache=shared&mode=rwc")

	_, err := Init(nil, true)
	if err != nil {
		t.Fatalf("Init() with default driver should use sqlite: %v", err)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat SQLite database: %v", err)
	}
	if got := info.Mode().Perm(); got != 0660 {
		t.Fatalf("SQLite permissions = %04o, want 0660", got)
	}
}

func TestInit_MySQL_MissingDSN(t *testing.T) {
	t.Setenv("DB_DRIVER", "mysql")
	_ = os.Unsetenv("DB_DSN")

	_, err := Init(nil, true)
	if err == nil {
		t.Error("expected error when DB_DRIVER=mysql and DB_DSN is empty")
	}
}

func TestInit_Postgres_MissingDSN(t *testing.T) {
	t.Setenv("DB_DRIVER", "postgres")
	_ = os.Unsetenv("DB_DSN")

	_, err := Init(nil, true)
	if err == nil {
		t.Error("expected error when DB_DRIVER=postgres and DB_DSN is empty")
	}
}
