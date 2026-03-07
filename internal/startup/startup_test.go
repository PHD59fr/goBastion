package startup

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"goBastion/internal/models"
)

const testPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test-key"

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.IngressKey{}, &models.SelfEgressKey{},
		&models.GroupEgressKey{}, &models.SelfAccess{}, &models.GroupAccess{},
		&models.Group{}, &models.UserGroup{}, &models.Aliases{},
		&models.KnownHostsEntry{}, &models.PIVTrustAnchor{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestBootstrap_createDBIngressKey_Valid(t *testing.T) {
	db := newTestDB(t)
	user := models.User{Username: "admin", Role: models.RoleAdmin, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := createDBIngressKey(db, &user, testPubKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var key models.IngressKey
	if err := db.Where("user_id = ?", user.ID).First(&key).Error; err != nil {
		t.Fatalf("key not found in DB: %v", err)
	}
	if key.Type == "" {
		t.Fatal("expected non-empty key type")
	}
}

func TestBootstrap_createDBIngressKey_Empty(t *testing.T) {
	db := newTestDB(t)
	user := models.User{Username: "admin", Role: models.RoleAdmin, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	err := createDBIngressKey(db, &user, "")
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
}

func TestBootstrap_createDBIngressKey_Invalid(t *testing.T) {
	db := newTestDB(t)
	user := models.User{Username: "admin", Role: models.RoleAdmin, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	err := createDBIngressKey(db, &user, "not-a-valid-key garbage!!!")
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
}
