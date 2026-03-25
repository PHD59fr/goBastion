package db

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/logger"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	dbDir      = "/var/lib/goBastion"
	dbConfFile = "/run/gobastion/db.conf"
)

// Init opens the database, runs migrations and applies configuration.
// resolveDBConfig returns DB_DRIVER and DB_DSN from environment variables, falling
// back to /run/gobastion/db.conf when the env vars are not set (e.g. SSH ForceCommand
// sessions where sshd strips the Docker environment).
func resolveDBConfig() (driver, dsn string) {
	driver = os.Getenv("DB_DRIVER")
	dsn = os.Getenv("DB_DSN")
	if driver != "" {
		return
	}

	f, err := os.Open(dbConfFile)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if k, v, ok := strings.Cut(line, "="); ok {
			switch k {
			case "DB_DRIVER":
				if driver == "" {
					driver = v
				}
			case "DB_DSN":
				if dsn == "" {
					dsn = v
				}
			}
		}
	}

	return
}

// Init opens the database, runs migrations and applies configuration.
// The database backend is selected via the DB_DRIVER environment variable:
//
//	DB_DRIVER=sqlite  (default) - SQLite file at /var/lib/goBastion/bastion.db
//	                              Override path with DB_DSN.
//	DB_DRIVER=mysql              - requires DB_DSN (e.g. "user:pass@tcp(host:3306)/dbname?charset=utf8mb4&parseTime=True")
//	DB_DRIVER=postgres           - requires DB_DSN (e.g. "host=... user=... password=... dbname=... port=5432 sslmode=disable")
//
// When env vars are absent (e.g. in an SSH ForceCommand session where sshd strips the
// environment), goBastion falls back to reading /run/gobastion/db.conf written by the
// entrypoint at container startup.
func Init(log *slog.Logger) (*gorm.DB, error) {
	driver, dsn := resolveDBConfig()

	var dialector gorm.Dialector
	switch driver {
	case "mysql":
		if dsn == "" {
			return nil, fmt.Errorf("DB_DSN is required when DB_DRIVER=mysql")
		}
		dialector = mysql.Open(dsn)

	case "postgres":
		if dsn == "" {
			return nil, fmt.Errorf("DB_DSN is required when DB_DRIVER=postgres")
		}
		dialector = postgres.Open(dsn)

	case "", "sqlite":
		driver = "sqlite"
		if dsn == "" {
			if err := os.MkdirAll(dbDir, 0777); err != nil {
				return nil, fmt.Errorf("failed to create DB directory %s: %w", dbDir, err)
			}
			dsn = "file:" + filepath.Join(dbDir, "bastion.db") + "?cache=shared&mode=rwc"
		}
		dialector = sqlite.Open(dsn)

	default:
		return nil, fmt.Errorf("unsupported DB_DRIVER %q — supported values: sqlite, mysql, postgres", driver)
	}

	gormLogCfg := gormLogger.Config{
		SlowThreshold: time.Second,
		LogLevel:      gormLogger.Silent,
		Colorful:      true,
	}

	var dbLog gormLogger.Interface
	if log != nil {
		dbLog = gormLogger.New(logger.NewGormLogger(log), gormLogCfg)
	} else {
		dbLog = gormLogger.Default.LogMode(gormLogger.Info)
	}

	db, err := gorm.Open(dialector, &gorm.Config{Logger: dbLog})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if log != nil {
		log.Info("db_connect", slog.String("event", "db_connect"), slog.String("driver", driver))
	}

	if err = migrate(db, driver); err != nil {
		return nil, fmt.Errorf("database migration failed for driver %s: %w", driver, err)
	}

	if log != nil {
		log.Info("db_migrate", slog.String("event", "db_migrate"), slog.String("driver", driver))
	}

	if driver == "postgres" {
		fixPostgresBoolColumns(db, log)
	}

	if err = configure(db, driver); err != nil {
		return nil, err
	}

	return db, nil
}

// fixPostgresBoolColumns ensures boolean-intended columns are of type boolean.
// Columns created by older images without explicit type tags may be text.
// Uses a USING expression safe for both text ('false'/'true') and boolean values.
func fixPostgresBoolColumns(db *gorm.DB, log *slog.Logger) {
	type colFix struct{ table, column string }

	fixes := []colFix{
		{"users", "system_user"},
		{"users", "enabled"},
		{"users", "totp_enabled"},
		{"groups", "mfa_required"},
		{"ingress_keys", "piv_attested"},
	}

	for _, f := range fixes {
		sql := fmt.Sprintf(
			`ALTER TABLE IF EXISTS "%s" ALTER COLUMN "%s" TYPE boolean `+
				`USING CASE WHEN "%s"::text = ANY(ARRAY['false','f','0','']) THEN false ELSE true END`,
			f.table, f.column, f.column,
		)

		if err := db.Exec(sql).Error; err != nil && log != nil {
			log.Warn("db_bool_migrate",
				slog.String("event", "db_bool_migrate"),
				slog.String("table", f.table),
				slog.String("column", f.column),
				slog.String("error_text", err.Error()),
			)
		}
	}
}

// migrate runs GORM AutoMigrate for all managed models and creates custom indexes.
func migrate(db *gorm.DB, driver string) error {
	err := db.AutoMigrate(
		&models.User{},
		&models.Group{},
		&models.UserGroup{},
		&models.IngressKey{},
		&models.SelfEgressKey{},
		&models.GroupEgressKey{},
		&models.SelfAccess{},
		&models.GroupAccess{},
		&models.Aliases{},
		&models.SshHostKey{},
		&models.KnownHostsEntry{},
		&models.PIVTrustAnchor{},
	)
	if err != nil {
		return fmt.Errorf("failed to auto-migrate models: %w", err)
	}

	switch driver {
	case "postgres", "sqlite":
		if err := db.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS unique_user_entry
			ON known_hosts_entries(user_id, entry)
			WHERE deleted_at IS NULL;
		`).Error; err != nil {
			return fmt.Errorf("failed to create unique_user_entry index: %w", err)
		}
		// Composite index for self access lookups (hot path: accessFilter + inferSSHUsername).
		if err := db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_self_access_lookup
			ON self_accesses(user_id, server, port, username, protocol)
			WHERE deleted_at IS NULL;
		`).Error; err != nil {
			return fmt.Errorf("failed to create idx_self_access_lookup: %w", err)
		}
		// Composite index for group access lookups.
		if err := db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_group_access_lookup
			ON group_accesses(group_id, server, port, username, protocol)
			WHERE deleted_at IS NULL;
		`).Error; err != nil {
			return fmt.Errorf("failed to create idx_group_access_lookup: %w", err)
		}
		// Composite index for user-group membership lookups.
		if err := db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_user_group_lookup
			ON user_groups(user_id, group_id)
			WHERE deleted_at IS NULL;
		`).Error; err != nil {
			return fmt.Errorf("failed to create idx_user_group_lookup: %w", err)
		}

	case "mysql":
		// MySQL does not support partial indexes (no WHERE clause) and column
		// type constraints make prefix lengths unreliable across configurations.
		// Index only the most selective leading columns; MySQL will use them to
		// narrow the row set before filtering on the remaining columns.
		if err := db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_self_access_lookup
			ON self_accesses(user_id);
		`).Error; err != nil {
			return fmt.Errorf("failed to create idx_self_access_lookup: %w", err)
		}
		if err := db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_group_access_lookup
			ON group_accesses(group_id);
		`).Error; err != nil {
			return fmt.Errorf("failed to create idx_group_access_lookup: %w", err)
		}
		if err := db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_user_group_lookup
			ON user_groups(user_id);
		`).Error; err != nil {
			return fmt.Errorf("failed to create idx_user_group_lookup: %w", err)
		}
	}

	return nil
}

// configure sets connection pool parameters and SQLite-specific pragmas (SQLite only).
func configure(db *gorm.DB, driver string) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get generic database object: %w", err)
	}

	// SQLite requires single-writer serialisation; Postgres/MySQL support real pools.
	switch driver {
	case "sqlite":
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	case "postgres", "mysql":
		sqlDB.SetMaxOpenConns(10)
		sqlDB.SetMaxIdleConns(5)
	default:
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	}
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	if driver == "sqlite" {
		db.Exec("PRAGMA journal_mode=WAL;")
		db.Exec("PRAGMA synchronous=NORMAL;")
		db.Exec("PRAGMA cache_size=-2000;")
		db.Exec("PRAGMA busy_timeout=20000;")
	}

	return nil
}

// BoolFalseExpr returns a SQL WHERE fragment matching rows where column is false/0.
// Dispatches to the correct expression based on the active database driver.
func BoolFalseExpr(db *gorm.DB, column string) string {
	switch db.Name() {
	case "postgres":
		return boolFalseExprPostgres(column)
	case "mysql":
		return boolFalseExprMySQL(column)
	case "sqlite":
		return boolFalseExprSQLite(column)
	default:
		return boolFalseExprSQLite(column)
	}
}

// BoolTrueExpr returns a SQL WHERE fragment matching rows where column is true/1.
// Dispatches to the correct expression based on the active database driver.
func BoolTrueExpr(db *gorm.DB, column string) string {
	switch db.Name() {
	case "postgres":
		return boolTrueExprPostgres(column)
	case "mysql":
		return boolTrueExprMySQL(column)
	case "sqlite":
		return boolTrueExprSQLite(column)
	default:
		return boolTrueExprSQLite(column)
	}
}

func ManagedModelsInDependencyOrder() []any {
	return []any{
		&models.User{},
		&models.Group{},
		&models.SshHostKey{},
		&models.UserGroup{},
		&models.IngressKey{},
		&models.SelfEgressKey{},
		&models.GroupEgressKey{},
		&models.SelfAccess{},
		&models.GroupAccess{},
		&models.Aliases{},
		&models.KnownHostsEntry{},
		&models.PIVTrustAnchor{},
	}
}
