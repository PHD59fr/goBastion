package account

import (
	"log/slog"
	"testing"
)

func TestDisablePassword_ValidationErrors(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	regular := newRegularUser(t, db, "regular")

	if err := DisablePassword(db, admin, slog.Default(), nil); err == nil {
		t.Fatal("expected missing username error")
	}
	if err := DisablePassword(db, regular, slog.Default(), []string{"--user", "admin"}); err == nil {
		t.Fatal("expected access-denied error")
	}
}

func TestDisableTOTP_ValidationErrors(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	regular := newRegularUser(t, db, "regular")

	if err := DisableTOTP(db, admin, slog.Default(), nil); err == nil {
		t.Fatal("expected missing username error")
	}
	if err := DisableTOTP(db, regular, slog.Default(), []string{"--user", "admin"}); err == nil {
		t.Fatal("expected access-denied error")
	}
}
