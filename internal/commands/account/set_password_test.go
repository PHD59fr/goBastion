package account

import (
	"log/slog"
	"testing"
)

func TestSetPassword_MissingArgsReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	if err := SetPassword(db, admin, slog.Default(), nil); err == nil {
		t.Fatal("expected missing required arguments error")
	}
}
