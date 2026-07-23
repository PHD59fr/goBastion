package account

import "testing"

func TestUnexpire_MissingArgsReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	if err := Unexpire(db, admin, []string{}); err == nil {
		t.Fatal("expected missing required arguments error")
	}
}

func TestUnexpire_AlreadyEnabledReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	newRegularUser(t, db, "alice")

	err := Unexpire(db, admin, []string{"--user", "alice"})
	if err == nil {
		t.Fatal("expected already enabled error")
	}
}
