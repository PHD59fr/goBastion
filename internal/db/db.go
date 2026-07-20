package db

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/logger"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

// resolveDBConfig returns DB_DRIVER and DB_DSN with precedence:
// environment variables > /run/gobastion/db.conf (written by entrypoint.sh) >
// in-memory defaults. The config file is the only way ForceCommand children
// (which run as the connected user with the Docker env stripped by sshd) learn
// the DB driver/DSN. Crucially the file MUST override the hardcoded "sqlite"
// default, otherwise children always fall back to SQLite.
func resolveDBConfig() (driver, dsn string) {
	// 1. Environment variables take highest precedence.
	driver = os.Getenv("DB_DRIVER")
	dsn = os.Getenv("DB_DSN")

	// 2. Fallback to the config file written by entrypoint.sh.
	if driver == "" {
		if f, err := os.Open(config.Get().Paths.DbConfFile); err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				if k, v, ok := strings.Cut(scanner.Text(), "="); ok {
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
			if scanErr := scanner.Err(); scanErr != nil {
				slog.Error("db_conf_read_error", slog.Any("error", scanErr))
			}
			_ = f.Close()
		}
	}

	// 3. Fallback to in-memory defaults (sqlite).
	if driver == "" {
		cfg := config.Get()
		driver = cfg.Database.Driver
		if dsn == "" {
			dsn = cfg.Database.DSN
		}
	}

	return
}

// Init opens the database, optionally runs migrations, and applies configuration.
// The database backend is selected via the DB_DRIVER environment variable:
//
//	DB_DRIVER=sqlite  (default) - SQLite file at /var/lib/goBastion/bastion.db
//	                              Override path with DB_DSN.
//	DB_DRIVER=mysql              - requires DB_DSN (e.g. "user:pass@tcp(host:3306)/dbname?charset=utf8mb4&parseTime=True")
//	DB_DRIVER=postgres           - requires DB_DSN (e.g. "host=... user=... password=... dbname=... port=5432 sslmode=disable")
//
// When env vars are absent, goBastion uses the in-memory defaults (sqlite).
// SSH ForceCommand sessions receive DB_DRIVER/DB_DSN via sshd SetEnv, so they
// connect to the same backend as the master process.
//
// When runMigrate is false (ForceCommand sessions), schema migration and index
// creation are skipped — only the master process (root) should run them.
func Init(log *slog.Logger, runMigrate bool) (*gorm.DB, error) {
	t0 := time.Now()
	cfg := config.Get()
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
			if err := os.MkdirAll(cfg.Paths.DbDir, 0750); err != nil {
				return nil, fmt.Errorf("failed to create DB directory %s: %w", cfg.Paths.DbDir, err)
			}
			dsn = "file:" + filepath.Join(cfg.Paths.DbDir, "bastion.db") + "?cache=shared&mode=rwc"
		}
		dialector = sqlite.Open(dsn)

	default:
		return nil, fmt.Errorf("unsupported DB_DRIVER %q — supported values: sqlite, mysql, postgres", driver)
	}

	gormLogCfg := gormLogger.Config{
		SlowThreshold: cfg.Database.SlowQueryThreshold,
		LogLevel:      gormLogger.Silent,
		Colorful:      true,
	}

	var dbLog gormLogger.Interface
	if log != nil {
		dbLog = gormLogger.New(logger.NewGormLogger(log), gormLogCfg)
	} else {
		dbLog = gormLogger.Default.LogMode(gormLogger.Info)
	}

	tConn := time.Now()
	db, err := gorm.Open(dialector, &gorm.Config{Logger: dbLog})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	if driver == "sqlite" {
		if err := ensureSQLitePermissions(dsn); err != nil {
			return nil, err
		}
	}
	if log != nil {
		log.Info("db_connect", slog.String("driver", driver), slog.Duration("took", time.Since(tConn)))
	}

	tMig := time.Now()
	if runMigrate {
		if err = migrate(db, driver); err != nil {
			return nil, fmt.Errorf("database migration failed for driver %s: %w", driver, err)
		}
		if log != nil {
			log.Info("db_migrate", slog.String("driver", driver), slog.Duration("took", time.Since(tMig)))
		}
	} else if log != nil {
		log.Info("db_migrate_skip", slog.String("reason", "non-root session"))
	}

	tBool := time.Now()
	if runMigrate && driver == "postgres" {
		fixPostgresBoolColumns(db, log)
	}
	if log != nil && driver == "postgres" {
		log.Info("db_bool_fix", slog.Duration("took", time.Since(tBool)))
	}

	tCfg := time.Now()
	if err = configure(db, driver); err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		if err := ensureSQLitePermissions(dsn); err != nil {
			return nil, err
		}
	}
	if log != nil {
		log.Info("db_configure", slog.Duration("took", time.Since(tCfg)))
	}

	if log != nil {
		log.Info("db_init_done", slog.Duration("total", time.Since(t0)))
	}

	return db, nil
}

// ensureSQLitePermissions keeps the database and its sidecar files writable
// by the container's gobastion group. The pure-Go SQLite driver creates the
// main file with 0644 regardless of the process umask.
func ensureSQLitePermissions(dsn string) error {
	path := strings.TrimPrefix(dsn, "file:")
	path, _, _ = strings.Cut(path, "?")
	if path == "" || path == ":memory:" {
		return nil
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect SQLite permissions on %s: %w", candidate, err)
		}
		if info.Mode().Perm() == 0660 {
			continue
		}
		if err := os.Chmod(candidate, 0660); err != nil {
			return fmt.Errorf("set SQLite permissions on %s: %w", candidate, err)
		}
	}
	return nil
}

// fixPostgresBoolColumns ensures boolean-intended columns are of type boolean.
// Columns created by older images without explicit type tags may be text.
// Uses a USING expression safe for both text ('false'/'true') and boolean values.
// Skips columns that are already boolean to avoid unnecessary ALTER TABLE locks.
func fixPostgresBoolColumns(db *gorm.DB, log *slog.Logger) {
	type colFix struct{ table, column string }

	fixes := []colFix{
		{"users", "system_user"},
		{"users", "enabled"},
		{"users", "osh_only"},
		{"users", "super_owner"},
		{"users", "totp_enabled"},
		{"groups", "mfa_required"},
		{"ingress_keys", "piv_attested"},
	}

	for _, f := range fixes {
		// Check current column type — skip if already boolean.
		var dataType string
		if err := db.Raw(
			`SELECT data_type FROM information_schema.columns WHERE table_name = ? AND column_name = ?`,
			f.table, f.column,
		).Scan(&dataType).Error; err != nil {
			continue
		}
		if dataType == "boolean" {
			continue
		}

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
				slog.String("error", err.Error()),
			)
		}
	}
}

// migrate runs GORM AutoMigrate for all managed models and creates custom indexes.
func migrate(db *gorm.DB, driver string) error {
	err := db.AutoMigrate(ManagedModelsInDependencyOrder()...)
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
		// MySQL does not support partial indexes (no WHERE clause).
		// Create composite indexes matching the PostgreSQL/SQLite ones.
		if err := db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_self_access_lookup
			ON self_accesses(user_id, server, port, username, protocol);
		`).Error; err != nil {
			return fmt.Errorf("failed to create idx_self_access_lookup: %w", err)
		}
		if err := db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_group_access_lookup
			ON group_accesses(group_id, server, port, username, protocol);
		`).Error; err != nil {
			return fmt.Errorf("failed to create idx_group_access_lookup: %w", err)
		}
		if err := db.Exec(`
			CREATE INDEX IF NOT EXISTS idx_user_group_lookup
			ON user_groups(user_id, group_id);
		`).Error; err != nil {
			return fmt.Errorf("failed to create idx_user_group_lookup: %w", err)
		}
	}

	return nil
}

// configure sets connection pool parameters and SQLite-specific pragmas (SQLite only).
func configure(db *gorm.DB, driver string) error {
	cfg := config.Get()
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
		sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
		sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	default:
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	}
	sqlDB.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	if driver == "sqlite" {
		pragmas := []string{
			"PRAGMA journal_mode=WAL;",
			"PRAGMA synchronous=NORMAL;",
			fmt.Sprintf("PRAGMA cache_size=-%d;", cfg.Database.SQLite.CacheSize),
			fmt.Sprintf("PRAGMA busy_timeout=%d;", cfg.Database.SQLite.BusyTimeout),
		}
		for _, p := range pragmas {
			if err := db.Exec(p).Error; err != nil {
				slog.Default().Error("sqlite_pragma_failed", slog.String("pragma", p), slog.String("error", err.Error()))
			}
		}
	}

	return nil
}

// allowedBoolColumns is the allowlist of column names that may be passed to
// BoolFalseExpr / BoolTrueExpr.  This prevents accidental SQL injection if a
// future caller passes user-controlled input.
var allowedBoolColumns = map[string]bool{
	"system_user":  true,
	"enabled":      true,
	"osh_only":     true,
	"super_owner":  true,
	"totp_enabled": true,
	"mfa_required": true,
	"piv_attested": true,
}

// validColumnName matches safe SQL column names: lowercase letters, digits, and underscores only.
var validColumnName = regexp.MustCompile(`^[a-z_]+$`)

// BoolFalseExpr returns a SQL WHERE fragment matching rows where column is false/0.
// Dispatches to the correct expression based on the active database driver.
// Panics (development) or returns a safe default (production) if the column
// name is not in the allowlist.
func BoolFalseExpr(db *gorm.DB, column string) string {
	if !allowedBoolColumns[column] || !validColumnName.MatchString(column) {
		return "1=0" // safe default: match nothing
	}
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
	if !allowedBoolColumns[column] || !validColumnName.MatchString(column) {
		return "1=0" // safe default: match nothing
	}
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
		&models.BastionInstance{},
		&models.User{},
		&models.Group{},
		&models.SshHostKey{},
		&models.UserGroup{},
		&models.IngressKey{},
		&models.SelfEgressKey{},
		&models.GroupEgressKey{},
		&models.SelfAccess{},
		&models.GroupAccess{},
		&models.GroupGuestAccess{},
		&models.Aliases{},
		&models.KnownHostsEntry{},
		&models.PIVTrustAnchor{},
		&models.Realm{},
		&models.RestrictedCommandGrant{},
	}
}
