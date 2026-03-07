package db

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// boolColumns lists the boolean columns per table.
// Required to convert int64 (0/1) values — produced by SQLite and MySQL drivers —
// into proper SQL boolean literals when the target dialect is PostgreSQL.
var boolColumns = map[string]map[string]bool{
	"users":        {"enabled": true, "system_user": true, "totp_enabled": true},
	"groups":       {"mfa_required": true},
	"ingress_keys": {"piv_attested": true},
}

// errWriter wraps an io.Writer and captures the first write error.
// Subsequent writes are no-ops once an error has occurred, so callers
// can chain writes freely and check w.err once at the end.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, a...)
}

func (ew *errWriter) println(a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w, a...)
}

// ExportTo writes a SQL script containing INSERT statements for every row
// (including soft-deleted rows) to w, formatted for targetDialect.
//
// Supported dialects: "sqlite", "mysql", "postgres".
//
// Usage:
//
// docker exec <ctr> goBastion --dbExportToMysql  > dump.sql
// docker exec <ctr> goBastion --dbExportToPg     > dump.sql
// docker exec <ctr> goBastion --dbExportToSqlite > dump.sql
//
// Before importing, run goBastion once against the target database so that
// AutoMigrate creates the schema, then apply the dump:
//
// mysql   -u user -p dbname  < dump.sql
// psql    -U user    dbname  < dump.sql
// sqlite3 bastion.db         < dump.sql
func ExportTo(src *gorm.DB, targetDialect string, w io.Writer, log *slog.Logger) error {
	switch targetDialect {
	case "sqlite", "mysql", "postgres":
	default:
		return fmt.Errorf("unsupported dialect %q — use sqlite, mysql, or postgres", targetDialect)
	}

	sqlDB, err := src.DB()
	if err != nil {
		return fmt.Errorf("failed to get DB handle: %w", err)
	}

	ew := &errWriter{w: w}
	sourceDialect := src.Name()

	ew.printf("-- goBastion database export\n")
	ew.printf("-- Generated : %s\n", time.Now().UTC().Format(time.RFC3339))
	ew.printf("-- Source    : %s\n", sourceDialect)
	ew.printf("-- Target    : %s\n", targetDialect)
	ew.printf("--\n")
	ew.printf("-- Before importing, run goBastion once with the target DB config\n")
	ew.printf("-- so that AutoMigrate creates the schema, then apply this file.\n\n")
	ew.println("BEGIN;")
	ew.println()

	switch targetDialect {
	case "mysql":
		ew.println("SET FOREIGN_KEY_CHECKS=0;")
		ew.println()
	case "postgres":
		ew.println("SET session_replication_role = replica;")
		ew.println()
	}

	if ew.err != nil {
		return fmt.Errorf("write header: %w", ew.err)
	}

	// Tables in FK-dependency order (parents before children).
	tables := []string{
		"users",
		"groups",
		"ssh_host_keys",
		"user_groups",
		"ingress_keys",
		"self_egress_keys",
		"group_egress_keys",
		"self_accesses",
		"group_accesses",
		"aliases",
		"known_hosts_entries",
		"piv_trust_anchors",
	}

	for _, table := range tables {
		if log != nil {
			log.Info("db_export", slog.String("event", "db_export"), slog.String("table", table))
		}
		if err := exportTable(sqlDB, ew, table, sourceDialect, targetDialect); err != nil {
			return fmt.Errorf("export table %q: %w", table, err)
		}
	}

	switch targetDialect {
	case "mysql":
		ew.println("SET FOREIGN_KEY_CHECKS=1;")
		ew.println()
	case "postgres":
		ew.println("SET session_replication_role = DEFAULT;")
		ew.println()
	}

	ew.println("COMMIT;")

	return ew.err
}

func exportTable(sqlDB *sql.DB, ew *errWriter, table, sourceDialect, targetDialect string) error {
	rows, err := sqlDB.Query(fmt.Sprintf("SELECT * FROM %s", quoteIdent(table, sourceDialect)))
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return err
	}

	ew.printf("-- Table: %s\n", table)

	quotedCols := make([]string, len(cols))
	for i, c := range cols {
		quotedCols[i] = quoteIdent(c, targetDialect)
	}
	header := fmt.Sprintf("INSERT INTO %s (%s) VALUES",
		quoteIdent(table, targetDialect),
		strings.Join(quotedCols, ", "),
	)

	boolCols := boolColumns[table]
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}

	rowCount := 0
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		fmtVals := make([]string, len(cols))
		for i, v := range vals {
			fmtVals[i] = formatValue(v, cols[i], boolCols, targetDialect)
		}
		ew.printf("%s (%s);\n", header, strings.Join(fmtVals, ", "))
		rowCount++
	}
	if rowCount == 0 {
		ew.println("-- (no rows)")
	}
	ew.println()

	if ew.err != nil {
		return fmt.Errorf("write: %w", ew.err)
	}
	return rows.Err()
}

// quoteIdent quotes a table or column name for the given dialect.
func quoteIdent(name, dialect string) string {
	switch dialect {
	case "mysql":
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	default: // sqlite, postgres
		return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	}
}

// formatValue converts a scanned database value to a SQL literal for targetDialect.
func formatValue(v any, colName string, boolCols map[string]bool, targetDialect string) string {
	if v == nil {
		return "NULL"
	}
	switch val := v.(type) {
	case bool:
		return formatBool(val)

	case int64:
		if boolCols[colName] {
			return formatBool(val != 0)
		}
		return strconv.FormatInt(val, 10)

	case int32:
		if boolCols[colName] {
			return formatBool(val != 0)
		}
		return strconv.FormatInt(int64(val), 10)

	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)

	case string:
		return "'" + escapeSQLString(val) + "'"

	case []byte:
		// The pgx driver returns PostgreSQL UUID columns as [16]byte, not []byte.
		// Plain []byte here means actual binary data (e.g. BLOB / BYTEA).
		return formatBytes(val, targetDialect)

	case [16]byte:
		// UUID value from the PostgreSQL pgx/v5 driver.
		return "'" + uuid.UUID(val).String() + "'"

	case time.Time:
		return "'" + val.UTC().Format("2006-01-02 15:04:05.999999999") + "'"

	default:
		return "'" + escapeSQLString(fmt.Sprintf("%v", val)) + "'"
	}
}

// formatBool returns TRUE or FALSE; accepted by all three supported dialects.
func formatBool(b bool) string {
	if b {
		return "TRUE"
	}
	return "FALSE"
}

func escapeSQLString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// formatBytes encodes binary data as an inline hex literal.
//
// PostgreSQL : '\xdeadbeef'
// SQLite / MySQL: X'deadbeef'
func formatBytes(b []byte, dialect string) string {
	h := hex.EncodeToString(b)
	if dialect == "postgres" {
		return `'\x` + h + `'`
	}
	return `X'` + h + `'`
}
