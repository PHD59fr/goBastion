package tty

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

func TestTtyList_NoArgs(t *testing.T) {
	db := newTestDB(t)
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	// No recordings dir exists; TtyList should not panic.
	// It returns an error (os.Stat fails) but must not panic.
	_ = TtyList(db, &user, []string{})
}
