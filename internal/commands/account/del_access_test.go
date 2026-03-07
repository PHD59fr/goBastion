package account

import (
	"testing"

	"goBastion/internal/models"
)

func TestAccountDelAccess_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	alice := newRegularUser(t, db, "alice")

	// Create an access entry directly
	access := models.SelfAccess{
		UserID:   alice.ID,
		Server:   "1.2.3.4",
		Username: "root",
		Port:     22,
		Protocol: "ssh",
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatalf("create access: %v", err)
	}

	err := AccountDelAccess(db, admin, []string{"--access", access.ID.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.SelfAccess{}).Where("id = ?", access.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected access to be deleted, count=%d", count)
	}
}

func TestAccountDelAccess_NotFound(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Non-existent UUID — function should not return error (it silently deletes 0 rows)
	_ = AccountDelAccess(db, admin, []string{"--access", "00000000-0000-0000-0000-000000000000"})
}
