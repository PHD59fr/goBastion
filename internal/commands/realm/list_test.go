package realm

import (
	"testing"

	"goBastion/internal/models"
)

func TestRealmList_Empty(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := List(db, admin, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRealmList_WithRealms(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Seed two realms directly via DB.
	for _, name := range []string{"alpha", "beta"} {
		r := models.Realm{
			Name:        name,
			BastionHost: name + ".example.com",
			BastionPort: 22,
			AllowedFrom: "10.0.0.0/8",
			PublicKey:   "ssh-ed25519 AAAA...",
			Enabled:     true,
			CreatedByID: admin.ID,
		}
		if err := db.Create(&r).Error; err != nil {
			t.Fatalf("seed realm %s: %v", name, err)
		}
	}

	err := List(db, admin, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.Realm{}).Count(&count)
	if count != 2 {
		t.Fatalf("expected 2 realms in DB, got %d", count)
	}
}
