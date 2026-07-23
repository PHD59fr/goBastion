package account

import "testing"

func TestModify_MissingArgsReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	if err := Modify(db, admin, []string{"--user", "alice"}); err == nil {
		t.Fatal("expected missing required arguments error")
	}
}

func TestModify_InvalidRoleReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	newRegularUser(t, db, "alice")

	err := Modify(db, admin, []string{
		"--user", "alice",
		"--sysrole", "invalid",
	})
	if err == nil {
		t.Fatal("expected invalid role error")
	}
}

func TestModify_InvalidBoolReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	newRegularUser(t, db, "alice")

	err := Modify(db, admin, []string{
		"--user", "alice",
		"--oshOnly", "maybe",
	})
	if err == nil {
		t.Fatal("expected invalid boolean error")
	}
}
