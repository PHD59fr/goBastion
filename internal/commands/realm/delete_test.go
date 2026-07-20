package realm

import (
	"testing"

	"goBastion/internal/models"
)

func TestRealmDelete_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	r := models.Realm{
		Name:        "todelete",
		BastionHost: "bastion.example.com",
		BastionPort: 22,
		AllowedFrom: "10.0.0.0/8",
		PublicKey:   "ssh-ed25519 AAAA...",
		Enabled:     true,
		CreatedByID: admin.ID,
	}
	if err := db.Create(&r).Error; err != nil {
		t.Fatalf("seed realm: %v", err)
	}

	err := Delete(db, admin, []string{"--realm", "todelete"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.Realm{}).Where("name = ?", "todelete").Count(&count)
	if count != 0 {
		t.Fatalf("expected realm to be soft-deleted, count=%d", count)
	}
}

func TestRealmDelete_NotFound(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Deleting a non-existent realm returns nil (no error).
	err := Delete(db, admin, []string{"--realm", "nonexistent"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRealmDelete_PermissionDenied(t *testing.T) {
	db := newTestDB(t)
	regular := newRegularUser(t, db, "regular")

	// The realmDelete permission requires admin, super_owner, or a grant.
	if regular.CanDo(db, "realmDelete", "") {
		t.Fatal("expected regular user to lack realmDelete permission")
	}
}
