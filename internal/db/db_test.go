package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"goBastion/internal/config"
	"goBastion/internal/models"
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
	var foreignKeys int
	if err := gormDB.Raw("PRAGMA foreign_keys").Scan(&foreignKeys).Error; err != nil {
		t.Fatalf("query foreign_keys pragma: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("PRAGMA foreign_keys = %d, want 1", foreignKeys)
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

func TestResolveDBConfig_UsesDBConfForMissingDSN(t *testing.T) {
	t.Setenv("DB_DRIVER", "postgres")
	_ = os.Unsetenv("DB_DSN")

	tmpDir := t.TempDir()
	dbConf := filepath.Join(tmpDir, "db.conf")
	if err := os.WriteFile(dbConf, []byte("DB_DRIVER=mysql\nDB_DSN=host=db.example user=test\n"), 0600); err != nil {
		t.Fatalf("write db.conf: %v", err)
	}

	cfg := config.Get()
	cfg.Paths.DbConfFile = dbConf

	driver, dsn := resolveDBConfig()
	if driver != "postgres" {
		t.Fatalf("driver = %q, want postgres", driver)
	}
	if dsn != "host=db.example user=test" {
		t.Fatalf("dsn = %q, want fallback from db.conf", dsn)
	}
}

func TestMigrateRejectsDuplicateActiveUsernamesWithoutDeletingData(t *testing.T) {
	database, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := database.AutoMigrate(&models.User{}); err != nil {
		t.Fatalf("migrate users: %v", err)
	}
	for _, username := range []string{"Alice", "alice"} {
		user := models.User{Username: username, Role: models.RoleUser, Enabled: true}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("seed duplicate user: %v", err)
		}
	}

	err = migrate(database, "sqlite")
	if err == nil || !strings.Contains(err.Error(), "duplicate active username") || !strings.Contains(err.Error(), "no data was deleted") {
		t.Fatalf("migrate error = %v, want clear non-destructive duplicate error", err)
	}
	var count int64
	if err := database.Model(&models.User{}).Count(&count).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 2 {
		t.Fatalf("migration changed duplicate rows: count=%d", count)
	}
}

func TestMigrateRejectsDuplicateMembershipsAndAliases(t *testing.T) {
	tests := []struct {
		name      string
		wantError string
		seed      func(*testing.T, *gorm.DB)
	}{
		{
			name:      "membership",
			wantError: "duplicate active user/group membership",
			seed: func(t *testing.T, database *gorm.DB) {
				user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
				group := models.Group{Name: "ops"}
				if err := database.Create(&user).Error; err != nil {
					t.Fatal(err)
				}
				if err := database.Create(&group).Error; err != nil {
					t.Fatal(err)
				}
				for _, role := range []string{models.GroupRoleMember, models.GroupRoleOwner} {
					if err := database.Create(&models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: role}).Error; err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name:      "personal alias",
			wantError: "duplicate active personal alias",
			seed: func(t *testing.T, database *gorm.DB) {
				user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
				if err := database.Create(&user).Error; err != nil {
					t.Fatal(err)
				}
				for _, alias := range []string{"Prod", "prod"} {
					if err := database.Create(&models.Aliases{ResolveFrom: alias, Host: "host.example", UserID: &user.ID}).Error; err != nil {
						t.Fatal(err)
					}
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatalf("open database: %v", err)
			}
			if err := database.AutoMigrate(ManagedModelsInDependencyOrder()...); err != nil {
				t.Fatalf("seed schema: %v", err)
			}
			test.seed(t, database)
			err = migrate(database, "sqlite")
			if err == nil || !strings.Contains(err.Error(), test.wantError) || !strings.Contains(err.Error(), "no data was deleted") {
				t.Fatalf("migrate error = %v, want %q non-destructive preflight error", err, test.wantError)
			}
		})
	}
}

func TestMigrateActiveIdentityConstraintsAllowSoftDeleteRecreation(t *testing.T) {
	database, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := migrate(database, "sqlite"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	caseDuplicate := models.User{Username: "ALICE", Role: models.RoleUser, Enabled: true}
	if err := database.Create(&caseDuplicate).Error; err == nil {
		t.Fatal("expected case-insensitive active username conflict")
	}
	if err := database.Delete(&user).Error; err != nil {
		t.Fatalf("soft-delete user: %v", err)
	}
	recreated := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := database.Create(&recreated).Error; err != nil {
		t.Fatalf("recreate soft-deleted username: %v", err)
	}

	group := models.Group{Name: "ops"}
	if err := database.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	membership := models.UserGroup{UserID: recreated.ID, GroupID: group.ID, Role: models.GroupRoleMember}
	if err := database.Create(&membership).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}
	if err := database.Create(&models.UserGroup{UserID: recreated.ID, GroupID: group.ID, Role: models.GroupRoleOwner}).Error; err == nil {
		t.Fatal("expected active membership conflict regardless of role")
	}
	if err := database.Delete(&membership).Error; err != nil {
		t.Fatalf("soft-delete membership: %v", err)
	}
	if err := database.Create(&models.UserGroup{UserID: recreated.ID, GroupID: group.ID, Role: models.GroupRoleOwner}).Error; err != nil {
		t.Fatalf("recreate soft-deleted membership: %v", err)
	}

	alias := models.Aliases{ResolveFrom: "Prod", Host: "one.example", UserID: &recreated.ID}
	if err := database.Create(&alias).Error; err != nil {
		t.Fatalf("create alias: %v", err)
	}
	if err := database.Create(&models.Aliases{ResolveFrom: "prod", Host: "two.example", UserID: &recreated.ID}).Error; err == nil {
		t.Fatal("expected case-insensitive personal alias conflict")
	}
	if err := database.Delete(&alias).Error; err != nil {
		t.Fatalf("soft-delete alias: %v", err)
	}
	if err := database.Create(&models.Aliases{ResolveFrom: "prod", Host: "two.example", UserID: &recreated.ID}).Error; err != nil {
		t.Fatalf("recreate soft-deleted alias: %v", err)
	}

	ingress := models.IngressKey{UserID: recreated.ID, Key: "key-one", Type: "ssh-ed25519", Size: 256, Fingerprint: "fingerprint"}
	if err := database.Create(&ingress).Error; err != nil {
		t.Fatalf("create ingress key: %v", err)
	}
	if err := database.Create(&models.IngressKey{UserID: recreated.ID, Key: "key-two", Type: "ssh-ed25519", Size: 256, Fingerprint: "fingerprint"}).Error; err == nil {
		t.Fatal("expected active ingress fingerprint conflict")
	}
	if err := database.Delete(&ingress).Error; err != nil {
		t.Fatalf("soft-delete ingress key: %v", err)
	}
	if err := database.Create(&models.IngressKey{UserID: recreated.ID, Key: "key-two", Type: "ssh-ed25519", Size: 256, Fingerprint: "fingerprint"}).Error; err != nil {
		t.Fatalf("recreate soft-deleted ingress key: %v", err)
	}
}
