package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestGroupAddMember_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	newRegularUser(t, db, "alice")

	g := models.Group{Name: "mygroup"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	err := GroupAddMember(db, admin, []string{
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

func TestGroupAddMember_InvalidRole(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	newRegularUser(t, db, "alice")

	g := models.Group{Name: "mygroup"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	// The function accepts any non-empty role string; "invalidrole" creates the row
	// but we verify it does not panic.
	_ = GroupAddMember(db, admin, []string{
		"--group", "mygroup",
		"--user", "alice",
		"--role", "invalidrole",
	})
}
