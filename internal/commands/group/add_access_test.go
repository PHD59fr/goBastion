package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestAddAccess_Success(t *testing.T) {
	for _, server := range []string{"10.0.0.1", "2001:db8::10", "[2001:db8::10]"} {
		t.Run(server, func(t *testing.T) {
			db := newTestDB(t)
			admin := newAdminUser(t, db, "admin")

			g := models.Group{Name: "mygroup"}
			if err := db.Create(&g).Error; err != nil {
				t.Fatalf("create group: %v", err)
			}

			err := AddAccess(db, admin, []string{
				"--group", "mygroup",
				"--server", server,
				"--username", "deploy",
				"--port", "22",
				"--force",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var saved models.GroupAccess
			if err := db.Where("group_id = ?", g.ID).First(&saved).Error; err != nil {
				t.Fatalf("read persisted group access: %v", err)
			}
			if saved.Server != server || saved.Port != 22 || saved.Username != "deploy" || saved.Protocol != "ssh" {
				t.Fatalf("unexpected persisted group access: %+v", saved)
			}
		})
	}
}

func TestAddAccess_DuplicateReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	g := models.Group{Name: "mygroup"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	if err := AddAccess(db, admin, []string{
		"--group", "mygroup",
		"--server", "10.0.0.1",
		"--username", "deploy",
		"--port", "22",
		"--force",
	}); err != nil {
		t.Fatalf("seed group access: %v", err)
	}

	err := AddAccess(db, admin, []string{
		"--group", "mygroup",
		"--server", "10.0.0.1",
		"--username", "deploy",
		"--port", "22",
		"--force",
	})
	if err == nil {
		t.Fatal("expected duplicate group access error")
	}
}
