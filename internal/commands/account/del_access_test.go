package account

import (
	"testing"

	"goBastion/internal/models"
)

func TestDelAccess_Success(t *testing.T) {
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

	err := DelAccess(db, admin, []string{"--access", access.ID.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.SelfAccess{}).Where("id = ?", access.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected access to be deleted, count=%d", count)
	}
}

func TestDelAccess_NotFound(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	if err := DelAccess(db, admin, []string{"--access", "00000000-0000-0000-0000-000000000000"}); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestDelAccess_ValidationErrors(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	regular := newRegularUser(t, db, "regular")

	if err := DelAccess(db, admin, nil); err == nil {
		t.Fatal("expected missing access ID error")
	}
	if err := DelAccess(db, admin, []string{"--access", "invalid"}); err == nil {
		t.Fatal("expected invalid access ID error")
	}
	if err := DelAccess(db, regular, []string{"--access", "00000000-0000-0000-0000-000000000000"}); err == nil {
		t.Fatal("expected access-denied error")
	}
}
