package realm

import (
	"testing"

	"goBastion/internal/models"
)

func TestRealmCreate_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := Create(db, admin, []string{
		"--realm", "remote-bastion",
		"--bastion", "bastion.example.com",
		"--port", "22",
		"--from", "10.0.0.0/8",
		"--public-key", "ssh-ed25519 AAAA...",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var r models.Realm
	if err := db.Where("name = ?", "remote-bastion").First(&r).Error; err != nil {
		t.Fatalf("realm not found in DB: %v", err)
	}
	if r.BastionHost != "bastion.example.com" {
		t.Fatalf("expected bastion host bastion.example.com, got %s", r.BastionHost)
	}
}

func TestRealmCreate_PermissionDenied(t *testing.T) {
	db := newTestDB(t)
	regular := newRegularUser(t, db, "regular")

	// The realmCreate permission requires admin, super_owner, or a grant.
	if regular.CanDo(db, "realmCreate", "") {
		t.Fatal("expected regular user to lack realmCreate permission")
	}
}

func TestRealmCreate_MissingArgs(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Missing --bastion, --from, --public-key triggers usage error.
	err := Create(db, admin, []string{"--realm", "myrealm"})
	if err != nil {
		t.Fatalf("expected nil (usage error prints and returns nil), got: %v", err)
	}

	var count int64
	db.Model(&models.Realm{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected no realm created, got %d", count)
	}
}
