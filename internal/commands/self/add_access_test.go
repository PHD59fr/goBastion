package self

import (
	"testing"

	"goBastion/internal/models"
)

func TestAddAccess_Success(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	err := AddAccess(db, user, []string{
		"--server", "1.2.3.4",
		"--username", "root",
		"--port", "22",
		"--force",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.SelfAccess{}).Where("user_id = ? AND server = ?", user.ID, "1.2.3.4").Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 access entry, got %d", count)
	}
}

func TestAddAccess_MissingServer(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	// Missing --server; should not panic, no DB entry
	_ = AddAccess(db, user, []string{
		"--username", "root",
		"--port", "22",
	})

	var count int64
	db.Model(&models.SelfAccess{}).Where("user_id = ?", user.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 access entries, got %d", count)
	}
}
