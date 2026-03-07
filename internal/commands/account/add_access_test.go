package account

import (
	"testing"

	"goBastion/internal/models"
)

func TestAccountAddAccess_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	newRegularUser(t, db, "alice")

	err := AccountAddAccess(db, admin, []string{
		"--user", "alice",
		"--server", "1.2.3.4",
		"--username", "root",
		"--port", "22",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.SelfAccess{}).Where("server = ? AND username = ?", "1.2.3.4", "root").Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 access entry, got %d", count)
	}
}

func TestAccountAddAccess_MissingServer(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	newRegularUser(t, db, "alice")

	// Missing --server; should not panic, should not create DB entry
	_ = AccountAddAccess(db, admin, []string{
		"--user", "alice",
		"--username", "root",
		"--port", "22",
	})

	var count int64
	db.Model(&models.SelfAccess{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 access entries, got %d", count)
	}
}

func TestAccountAddAccess_UserNotFound(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := AccountAddAccess(db, admin, []string{
		"--user", "unknown",
		"--server", "1.2.3.4",
		"--username", "root",
		"--port", "22",
	})
	if err == nil {
		t.Fatal("expected error for unknown user, got nil")
	}
}
