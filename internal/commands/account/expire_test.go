package account

import "testing"

func TestExpire_MissingArgsReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	if err := Expire(db, admin, []string{}); err == nil {
		t.Fatal("expected missing required arguments error")
	}
}

func TestExpire_SelfLockReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := Expire(db, admin, []string{"--user", "admin"})
	if err == nil {
		t.Fatal("expected self-lock error")
	}
}

func TestExpire_LastAdminReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	target := newAdminUser(t, db, "other-admin")
	if err := db.Delete(target).Error; err != nil {
		t.Fatalf("delete second admin: %v", err)
	}

	err := Expire(db, admin, []string{"--user", "admin"})
	if err == nil {
		t.Fatal("expected last-admin protection error")
	}
}
