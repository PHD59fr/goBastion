package realm

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"goBastion/internal/models"
	"golang.org/x/crypto/ssh"
)

func TestDeletedRealmCanBeRecreated(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	args := []string{"--realm", "fixture", "--bastion", "fixture.example", "--from", "10.0.0.0/8", "--public-key", testRealmPublicKey}
	if err := Create(db, admin, args); err != nil {
		t.Fatal(err)
	}
	if err := Delete(db, admin, []string{"--realm", "fixture"}); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	replacementKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	args = []string{"--realm", "fixture", "--bastion", "replacement.example", "--port", "2222", "--from", "192.0.2.0/24", "--public-key", replacementKey}
	if err := Create(db, admin, args); err != nil {
		t.Fatalf("deleted realm cannot be recreated: %v", err)
	}
	var realm models.Realm
	if err := db.First(&realm).Error; err != nil {
		t.Fatal(err)
	}
	if realm.BastionHost != "replacement.example" || realm.BastionPort != 2222 || realm.AllowedFrom != "192.0.2.0/24" || realm.PublicKey != replacementKey || !realm.Enabled {
		t.Fatalf("old trust configuration was restored: %+v", realm)
	}
	var count int64
	if err := db.Unscoped().Model(&models.Realm{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("restoration created duplicate realm names: %d %v", count, err)
	}
}
