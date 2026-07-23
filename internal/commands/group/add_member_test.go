package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestAddMember_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	newRegularUser(t, db, "alice")

	g := models.Group{Name: "mygroup"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	err := AddMember(db, admin, []string{
		"--group", "mygroup",
		"--user", "alice",
		"--role", "member",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var ug models.UserGroup
	if err := db.Where("group_id = ?", g.ID).First(&ug).Error; err != nil {
		t.Fatalf("UserGroup row not found: %v", err)
	}
	if ug.Role != "member" {
		t.Fatalf("expected role=member, got %s", ug.Role)
	}
}

func TestAddMember_InvalidRole(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	newRegularUser(t, db, "alice")

	g := models.Group{Name: "mygroup"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	err := AddMember(db, admin, []string{
		"--group", "mygroup",
		"--user", "alice",
		"--role", "invalidrole",
	})
	if err == nil {
		t.Fatal("expected invalid role error")
	}
}

func TestAddMember_DuplicateReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	alice := newRegularUser(t, db, "alice")

	g := models.Group{Name: "mygroup"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.Create(&models.UserGroup{UserID: alice.ID, GroupID: g.ID, Role: models.GroupRoleMember}).Error; err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	err := AddMember(db, admin, []string{
		"--group", "mygroup",
		"--user", "alice",
		"--role", "member",
	})
	if err == nil {
		t.Fatal("expected duplicate member error")
	}
}
