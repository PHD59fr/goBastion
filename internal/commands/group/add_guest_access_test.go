package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestAddGuestAccess_WrongRoleReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	alice := newRegularUser(t, db, "alice")

	group := models.Group{Name: "mygroup"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.Create(&models.UserGroup{UserID: alice.ID, GroupID: group.ID, Role: models.GroupRoleMember}).Error; err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	err := AddGuestAccess(db, admin, []string{
		"--group", "mygroup",
		"--account", "alice",
		"--host", "10.0.0.2",
		"--user", "deploy",
		"--port", "22",
	})
	if err == nil {
		t.Fatal("expected wrong role error")
	}
}

func TestAddGuestAccess_DuplicateReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	alice := newRegularUser(t, db, "alice")

	group := models.Group{Name: "mygroup"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.Create(&models.UserGroup{UserID: alice.ID, GroupID: group.ID, Role: models.GroupRoleGuest}).Error; err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	if err := db.Create(&models.GroupGuestAccess{
		GroupID:  group.ID,
		UserID:   alice.ID,
		Server:   "10.0.0.2",
		Port:     22,
		Username: "deploy",
		Protocol: "ssh",
	}).Error; err != nil {
		t.Fatalf("seed guest access: %v", err)
	}

	err := AddGuestAccess(db, admin, []string{
		"--group", "mygroup",
		"--account", "alice",
		"--host", "10.0.0.2",
		"--user", "deploy",
		"--port", "22",
	})
	if err == nil {
		t.Fatal("expected duplicate guest access error")
	}
}
