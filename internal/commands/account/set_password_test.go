package account

import (
	"log/slog"
	"testing"

	"goBastion/internal/models"
)

func TestSetPassword_MissingArgsReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	if err := SetPassword(db, admin, slog.Default(), nil); err == nil {
		t.Fatal("expected missing required arguments error")
	}
}

func TestSetPassword_Clear(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	target := newRegularUser(t, db, "alice")
	if err := db.Model(target).Update("password_hash", "existing hash").Error; err != nil {
		t.Fatalf("seed password hash: %v", err)
	}

	if err := SetPassword(db, admin, slog.Default(), []string{"--user", target.Username, "--clear"}); err != nil {
		t.Fatalf("SetPassword --clear: %v", err)
	}
	var refreshed models.User
	if err := db.First(&refreshed, "id = ?", target.ID).Error; err != nil {
		t.Fatalf("reload target: %v", err)
	}
	if refreshed.PasswordHash != "" {
		t.Fatalf("password hash = %q, want empty", refreshed.PasswordHash)
	}
}
