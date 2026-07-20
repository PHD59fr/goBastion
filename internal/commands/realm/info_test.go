package realm

import (
	"testing"

	"goBastion/internal/models"
)

func TestRealmInfo_Found(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	r := models.Realm{
		Name:        "myrealm",
		BastionHost: "bastion.example.com",
		BastionPort: 2222,
		AllowedFrom: "10.0.0.0/8",
		PublicKey:   "ssh-ed25519 AAAA...",
		Enabled:     true,
		CreatedByID: admin.ID,
	}
	if err := db.Create(&r).Error; err != nil {
		t.Fatalf("seed realm: %v", err)
	}

	err := Info(db, admin, []string{"--realm", "myrealm"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRealmInfo_NotFound(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := Info(db, admin, []string{"--realm", "nonexistent"})
	if err == nil {
		t.Fatal("expected error for non-existent realm, got nil")
	}
}
