package db

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"goBastion/models"
	"goBastion/utils/logger"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const dbDir = "/var/lib/goBastion"

// Init opens the database, runs migrations and applies configuration.
// The database backend is selected via the DB_DRIVER environment variable:
//
//	DB_DRIVER=sqlite  (default) — SQLite file at /var/lib/goBastion/bastion.db
//	                              Override path with DB_DSN.
//	DB_DRIVER=mysql              — requires DB_DSN (e.g. "user:pass@tcp(host:3306)/dbname?charset=utf8mb4&parseTime=True")
//	DB_DRIVER=postgres           — requires DB_DSN (e.g. "host=... user=... password=... dbname=... port=5432 sslmode=disable")
func Init(log *slog.Logger) (*gorm.DB, error) {
	driver := os.Getenv("DB_DRIVER")
	dsn := os.Getenv("DB_DSN")

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

	default: // sqlite
		if dsn == "" {
			if err := os.MkdirAll(dbDir, 0777); err != nil {
				return nil, fmt.Errorf("failed to create DB directory %s: %w", dbDir, err)
			}
			dsn = "file:" + filepath.Join(dbDir, "bastion.db") + "?cache=shared&mode=rwc"
		}
		dialector = sqlite.Open(dsn)
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
		dbLog = gormLogger.Default.LogMode(gormLogger.Silent)
	}

	db, err := gorm.Open(dialector, &gorm.Config{Logger: dbLog})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err = migrate(db); err != nil {
		return nil, err
	}

	if err = configure(db); err != nil {
		return nil, err
	}

	return db, nil
}

// migrate runs GORM AutoMigrate for all models and creates custom indexes.
func migrate(db *gorm.DB) error {
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
	)
	if err != nil {
		return fmt.Errorf("failed to auto-migrate models: %w", err)
	}

	db.Exec(`
		CREATE UNIQUE INDEX IF NOT EXISTS unique_user_entry
		ON known_hosts_entries(user_id, entry)
		WHERE deleted_at IS NULL;
	`)
	return nil
}

// configure sets connection pool parameters and SQLite pragmas.
func configure(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get generic database object: %w", err)
	}

	sqlDB.SetMaxOpenConns(2)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	db.Exec("PRAGMA journal_mode=WAL;")
	db.Exec("PRAGMA synchronous=NORMAL;")
	db.Exec("PRAGMA cache_size=-2000;")
	db.Exec("PRAGMA busy_timeout=20000;")

	return nil
}
