package self

import (
	"testing"

	"goBastion/internal/models"
)

func TestAddAccess_Success(t *testing.T) {
	for _, server := range []string{"1.2.3.4", "2001:db8::10", "[2001:db8::10]"} {
		t.Run(server, func(t *testing.T) {
			db := newTestDB(t)
			user := newRegularUser(t, db, "alice")

			err := AddAccess(db, user, []string{
				"--server", server,
				"--username", "root",
				"--port", "22",
				"--force",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var saved models.SelfAccess
			if err := db.Where("user_id = ?", user.ID).First(&saved).Error; err != nil {
				t.Fatalf("read persisted access: %v", err)
			}
			if saved.Server != server || saved.Port != 22 || saved.Username != "root" || saved.Protocol != "ssh" {
				t.Fatalf("unexpected persisted access: %+v", saved)
			}
		})
	}
}

func TestAddAccess_MissingServer(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	// Missing --server; should not panic, no DB entry
	err := AddAccess(db, user, []string{
		"--username", "root",
		"--port", "22",
	})
	if err == nil {
		t.Fatal("expected missing required arguments error")
	}

	var count int64
	db.Model(&models.SelfAccess{}).Where("user_id = ?", user.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 access entries, got %d", count)
	}
}

func TestAddAccess_DuplicateReturnsError(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := AddAccess(db, user, []string{
		"--server", "1.2.3.4",
		"--username", "root",
		"--port", "22",
		"--force",
	}); err != nil {
		t.Fatalf("seed access: %v", err)
	}

	err := AddAccess(db, user, []string{
		"--server", "1.2.3.4",
		"--username", "root",
		"--port", "22",
		"--force",
	})
	if err == nil {
		t.Fatal("expected duplicate access error")
	}
}
