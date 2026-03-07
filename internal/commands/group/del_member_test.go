package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestGroupDelMember_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	alice := newRegularUser(t, db, "alice")

	g := models.Group{Name: "mygroup"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	ug := models.UserGroup{UserID: alice.ID, GroupID: g.ID, Role: "member"}
	if err := db.Create(&ug).Error; err != nil {
		t.Fatalf("create user group: %v", err)
	}

	err := GroupDelMember(db, admin, []string{
		"--group", "mygroup",
		"--user", "alice",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.UserGroup{}).Where("user_id = ? AND group_id = ?", alice.ID, g.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected UserGroup row to be deleted, count=%d", count)
	}
}
