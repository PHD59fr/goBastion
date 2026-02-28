package commands

import (
	"os"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	"goBastion/models"
)

// newTestDB creates an in-memory SQLite database with all models migrated.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormLogger.Default.LogMode(gormLogger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	if err = db.AutoMigrate(
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
	); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	return db
}

// A minimal but syntactically valid RSA public key for testing (not cryptographically secure).
const validPubKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQ2U5kn0pxOb/G5yqxLNuW4y468oxd4KzEHt6b+FqPX5ZbzqXFcU6NnC4/PGF7DKT7yS9bDp7B99SNTj8+ipxbSh test@test"

func TestCreateDBIngressKey_Valid(t *testing.T) {
	db := newTestDB(t)
	user := &models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	if err := CreateDBIngressKey(db, user, validPubKey); err != nil {
		t.Errorf("expected no error for valid key, got: %v", err)
	}

	var count int64
	db.Model(&models.IngressKey{}).Where("user_id = ?", user.ID).Count(&count)
	if count != 1 {
		t.Errorf("expected 1 ingress key in DB, got %d", count)
	}
}

func TestCreateDBIngressKey_InvalidKey(t *testing.T) {
	db := newTestDB(t)
	user := &models.User{Username: "bob", Role: models.RoleUser, Enabled: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	err := CreateDBIngressKey(db, user, "not-a-valid-ssh-key")
	if err == nil {
		t.Error("expected error for invalid SSH key, got nil")
	}
}

func TestCreateDBIngressKey_Empty(t *testing.T) {
	db := newTestDB(t)
	user := &models.User{Username: "carol", Role: models.RoleUser, Enabled: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	err := CreateDBIngressKey(db, user, "")
	if err == nil {
		t.Error("expected error for empty SSH key, got nil")
	}
}

func TestCreateDBIngressKey_Duplicate(t *testing.T) {
	db := newTestDB(t)
	user := &models.User{Username: "dave", Role: models.RoleUser, Enabled: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	if err := CreateDBIngressKey(db, user, validPubKey); err != nil {
		t.Fatalf("first insert should succeed: %v", err)
	}

	if err := CreateDBIngressKey(db, user, validPubKey); err == nil {
		t.Error("expected error on duplicate key, got nil")
	}
}

func TestSwitchSysRoleUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root to write /etc/sudoers.d/")
	}
	db := newTestDB(t)

	// Create user via createDBUser (unexported, call via CreateUser path).
	user := &models.User{Username: "eve", Role: models.RoleUser, Enabled: true}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	if err := SwitchSysRoleUser(db, "eve"); err != nil {
		t.Fatalf("SwitchSysRoleUser error: %v", err)
	}

	var updated models.User
	db.Where("username = ?", "eve").First(&updated)
	if !updated.IsAdmin() {
		t.Errorf("expected user to be admin after SwitchSysRoleUser, got role=%q", updated.Role)
	}
}
