package db

import (
	"database/sql"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func createLegacyBooleanFixture(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, statement := range []string{
		`CREATE TABLE users (id integer PRIMARY KEY, "system_user" text, enabled text, osh_only text, super_owner text, totp_enabled text)`,
		`CREATE TABLE groups (id integer PRIMARY KEY, mfa_required text)`,
		`CREATE TABLE ingress_keys (id integer PRIMARY KEY, piv_attested text)`,
	} {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func insertLegacyBooleanFixture(t *testing.T, db *gorm.DB, id int, value any) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)`,
		`INSERT INTO groups VALUES (?, ?)`,
		`INSERT INTO ingress_keys VALUES (?, ?)`,
	} {
		args := []any{id, value}
		if strings.Contains(statement, "INTO users") {
			args = []any{id, value, value, value, value, value}
		}
		if err := db.Exec(statement, args...).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPostgresBooleanMigrationPreservesRecognizedValuesAndNull(t *testing.T) {
	db, _ := postgresMigrationTestDB(t)
	createLegacyBooleanFixture(t, db)
	values := []struct {
		text any
		want sql.NullBool
	}{
		{"true", sql.NullBool{Bool: true, Valid: true}},
		{"t", sql.NullBool{Bool: true, Valid: true}},
		{"1", sql.NullBool{Bool: true, Valid: true}},
		{" TrUe ", sql.NullBool{Bool: true, Valid: true}},
		{"false", sql.NullBool{Valid: true}},
		{"f", sql.NullBool{Valid: true}},
		{"0", sql.NullBool{Valid: true}},
		{"", sql.NullBool{Valid: true}},
		{" FALSE ", sql.NullBool{Valid: true}},
		{nil, sql.NullBool{}},
	}
	for i, value := range values {
		insertLegacyBooleanFixture(t, db, i, value.text)
	}
	if err := fixPostgresBoolColumns(db); err != nil {
		t.Fatal(err)
	}
	for _, column := range []struct{ table, name string }{
		{"users", "system_user"}, {"users", "enabled"}, {"users", "osh_only"},
		{"users", "super_owner"}, {"users", "totp_enabled"},
		{"groups", "mfa_required"}, {"ingress_keys", "piv_attested"},
	} {
		var dataType string
		if err := db.Raw(`SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?`, column.table, column.name).Scan(&dataType).Error; err != nil {
			t.Fatal(err)
		}
		if dataType != "boolean" {
			t.Fatalf("%s.%s remains %s", column.table, column.name, dataType)
		}
		for i, value := range values {
			var got sql.NullBool
			if err := db.Raw(`SELECT "`+column.name+`" FROM "`+column.table+`" WHERE id = ?`, i).Row().Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != value.want {
				t.Fatalf("%s.%s row %d: got %+v, want %+v", column.table, column.name, i, got, value.want)
			}
		}
	}
	// A repeated migration must preserve both converted values and nullability.
	if err := fixPostgresBoolColumns(db); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
}

func TestPostgresBooleanMigrationRefusesAmbiguousValues(t *testing.T) {
	for _, test := range []struct{ table, column, invalid string }{
		{"users", "enabled", "disabled"},
		{"users", "super_owner", "unexpected-admin-value"},
		{"groups", "mfa_required", "2"},
		{"ingress_keys", "piv_attested", "yes"},
	} {
		t.Run(test.table+"."+test.column, func(t *testing.T) {
			db, _ := postgresMigrationTestDB(t)
			createLegacyBooleanFixture(t, db)
			insertLegacyBooleanFixture(t, db, 1, "false")
			insertLegacyBooleanFixture(t, db, 2, nil)
			if err := db.Exec(`UPDATE "`+test.table+`" SET "`+test.column+`" = ? WHERE id = 1`, test.invalid).Error; err != nil {
				t.Fatal(err)
			}
			err := fixPostgresBoolColumns(db)
			if err == nil || !strings.Contains(err.Error(), "refusing ambiguous PostgreSQL boolean values") {
				t.Fatalf("expected explicit refusal, got %v", err)
			}
			if strings.Contains(err.Error(), test.invalid) {
				t.Fatal("migration refusal exposed the stored value")
			}
			var original sql.NullString
			if err := db.Raw(`SELECT "` + test.column + `" FROM "` + test.table + `" WHERE id = 1`).Row().Scan(&original); err != nil {
				t.Fatal(err)
			}
			if !original.Valid || original.String != test.invalid {
				t.Fatalf("refused value was changed: %+v", original)
			}
			var null sql.NullString
			if err := db.Raw(`SELECT "` + test.column + `" FROM "` + test.table + `" WHERE id = 2`).Row().Scan(&null); err != nil {
				t.Fatal(err)
			}
			if null.Valid {
				t.Fatal("refused column's NULL was changed")
			}
			var dataType string
			if err := db.Raw(`SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?`, test.table, test.column).Scan(&dataType).Error; err != nil {
				t.Fatal(err)
			}
			if dataType != "text" {
				t.Fatalf("refused column changed type to %s", dataType)
			}
		})
	}
}
