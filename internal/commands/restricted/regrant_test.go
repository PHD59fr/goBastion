package restricted

import (
	"testing"

	"goBastion/internal/models"
)

func TestRestrictedGrantCanBeRestored(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	_ = newRegularUser(t, db, "alice")
	args := []string{"--user", "alice", "--command", "realmCreate"}
	if err := GrantAdd(db, admin, args); err != nil {
		t.Fatal(err)
	}
	if err := GrantDel(db, admin, args); err != nil {
		t.Fatal(err)
	}
	admin = newAdminUser(t, db, "replacement-admin")
	if err := GrantAdd(db, admin, args); err != nil {
		t.Fatalf("revoked grant cannot be restored: %v", err)
	}
	var grant models.RestrictedCommandGrant
	if err := db.First(&grant).Error; err != nil {
		t.Fatal(err)
	}
	if grant.GrantedByID != admin.ID {
		t.Fatal("restored grant kept the old administrator")
	}
	if err := GrantAdd(db, admin, args); err == nil {
		t.Fatal("duplicate active grant accepted")
	}
	if err := GrantDel(db, admin, args); err != nil {
		t.Fatal(err)
	}
	if err := GrantAdd(db, admin, args); err != nil {
		t.Fatalf("second restoration failed: %v", err)
	}
	var count int64
	if err := db.Unscoped().Model(&models.RestrictedCommandGrant{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("restoration created duplicate history rows: %d %v", count, err)
	}
}
