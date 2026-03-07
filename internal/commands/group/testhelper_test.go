package group

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"goBastion/internal/models"
)

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

func newAdminUser(t *testing.T, db *gorm.DB, username string) *models.User {
	t.Helper()
	u := models.User{Username: username, Role: models.RoleAdmin, Enabled: true}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	return &u
}

func newRegularUser(t *testing.T, db *gorm.DB, username string) *models.User {
	t.Helper()
	u := models.User{Username: username, Role: models.RoleUser, Enabled: true}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("create regular user: %v", err)
	}
	return &u
}
