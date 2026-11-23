package db

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"goBastion/internal/models"
)

const exportUpgradeKey = "0123456789abcdef0123456789abcdef"

func openExportUpgradeDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "upgrade.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.AutoMigrate(ManagedModelsInDependencyOrder()...); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestExportUpgradeRevocationEpoch(t *testing.T) {
	t.Setenv("DB_EXPORT_KEY", exportUpgradeKey)
	for _, legacy := range []bool{true, false} {
		name := "current"
		if legacy {
			name = "previous_schema"
		}
		t.Run(name, func(t *testing.T) {
			source := openExportUpgradeDB(t)
			users := []models.User{
				{Username: "enabled", Role: models.RoleUser, RevocationEpoch: 7, LastLoginFrom: "192.0.2.1"},
				{Username: "retired", Role: models.RoleUser, RevocationEpoch: 9, DeletedAt: gorm.DeletedAt{Time: time.Now().UTC().Truncate(time.Second), Valid: true}},
			}
			for i := range users {
				if err := source.Create(&users[i]).Error; err != nil {
					t.Fatal(err)
				}
			}
			if legacy {
				if err := source.Exec("ALTER TABLE users DROP COLUMN revocation_epoch").Error; err != nil {
					t.Fatal(err)
				}
			}
			var backup bytes.Buffer
			if err := Export(source, &backup, nil); err != nil {
				t.Fatal(err)
			}
			// The backup path must not migrate or otherwise write its source.
			if got := source.Migrator().HasColumn(&models.User{}, "revocation_epoch"); got == legacy {
				t.Fatalf("source epoch column present = %t, legacy = %t", got, legacy)
			}
			target := openExportUpgradeDB(t)
			if err := Import(target, &backup, nil); err != nil {
				t.Fatal(err)
			}
			for _, want := range users {
				var got models.User
				if err := target.Unscoped().First(&got, "id = ?", want.ID).Error; err != nil {
					t.Fatal(err)
				}
				if legacy {
					want.RevocationEpoch = 0
				}
				if got.Username != want.Username || got.RevocationEpoch != want.RevocationEpoch || got.LastLoginFrom != want.LastLoginFrom || got.DeletedAt.Valid != want.DeletedAt.Valid {
					t.Fatalf("restored account differs: username=%q epoch=%d last_login_from=%q deleted=%t", got.Username, got.RevocationEpoch, got.LastLoginFrom, got.DeletedAt.Valid)
				}
			}
		})
	}
}

func TestExportUpgradeRejectsOtherMissingUserColumn(t *testing.T) {
	t.Setenv("DB_EXPORT_KEY", exportUpgradeKey)
	source := openExportUpgradeDB(t)
	if err := source.Exec("ALTER TABLE users DROP COLUMN system_user").Error; err != nil {
		t.Fatal(err)
	}
	var backup bytes.Buffer
	err := Export(source, &backup, nil)
	if err == nil || !strings.Contains(err.Error(), "required users column system_user is missing") {
		t.Fatalf("unexpected export result: %v", err)
	}
	if backup.Len() != 0 {
		t.Fatal("failed backup published output")
	}
}

// This fixture drops a schema column and must only use the disposable backend
// supplied by scripts/test-export-lifecycle-backends.sh, never a deployment DSN.
func TestBackendExportUpgradeRevocationEpoch(t *testing.T) {
	driver, dsn := os.Getenv("GOB_EXPORT_LIFECYCLE_DRIVER"), os.Getenv("GOB_EXPORT_LIFECYCLE_DSN")
	if driver == "" || dsn == "" {
		t.Skip("disposable export-lifecycle backend is not configured")
	}
	var dialect gorm.Dialector
	switch driver {
	case "mysql":
		dialect = mysql.Open(dsn)
	case "postgres":
		dialect = postgres.Open(dsn)
	default:
		t.Fatal("GOB_EXPORT_LIFECYCLE_DRIVER must be mysql or postgres")
	}
	source, err := gorm.Open(dialect, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open disposable %s database failed (%T)", driver, err)
	}
	pool, err := source.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = pool.Close() })
	if err := source.AutoMigrate(ManagedModelsInDependencyOrder()...); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DB_EXPORT_KEY", exportUpgradeKey)
	user := models.User{Username: "export-upgrade-" + uuid.NewString(), Role: models.RoleUser, RevocationEpoch: 7, LastLoginFrom: "192.0.2.1"}
	if err := source.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.AutoMigrate(&models.User{}); err != nil {
			t.Errorf("restore disposable users schema: %v", err)
		}
		if err := source.Exec("DELETE FROM users WHERE id = ?", user.ID).Error; err != nil {
			t.Errorf("remove upgrade fixture: %v", err)
		}
	})
	for _, legacy := range []bool{false, true} {
		if legacy {
			if err := source.Exec("ALTER TABLE users DROP COLUMN revocation_epoch").Error; err != nil {
				t.Fatal(err)
			}
			// Model an offline binary starting on the old schema. Retire the
			// connections whose PostgreSQL prepared SELECT * saw the new schema
			// before this fixture deliberately removed its column.
			pool.SetMaxIdleConns(0)
		}
		var backup bytes.Buffer
		if err := Export(source, &backup, nil); err != nil {
			t.Fatal(err)
		}
		if got := source.Migrator().HasColumn(&models.User{}, "revocation_epoch"); got == legacy {
			t.Fatalf("source epoch column present = %t, legacy = %t", got, legacy)
		}
		found := false
		for _, table := range decodeLifecycleExport(t, backup.Bytes()).Tables {
			if table.Name != "users" {
				continue
			}
			for _, row := range table.Rows {
				if row["id"].Value != user.ID.String() {
					continue
				}
				found = true
				want := strconv.FormatInt(user.RevocationEpoch, 10)
				if legacy {
					want = "0"
				}
				if row["revocation_epoch"].Value != want || row["username"].Value != user.Username || row["last_login_from"].Value != user.LastLoginFrom {
					t.Fatalf("exported account differs, legacy = %t", legacy)
				}
			}
		}
		if !found {
			t.Fatal("export omitted the fixture account")
		}
		var unchanged string
		if err := source.Raw("SELECT last_login_from FROM users WHERE id = ?", user.ID).Scan(&unchanged).Error; err != nil || unchanged != user.LastLoginFrom {
			t.Fatalf("source account changed: %v", err)
		}
	}
}
