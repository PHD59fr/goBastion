package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestGroupAddAccess_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	g := models.Group{Name: "mygroup"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	err := GroupAddAccess(db, admin, []string{
		"--group", "mygroup",
		"--server", "10.0.0.1",
		"--username", "deploy",
		"--port", "22",
		"--force",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.GroupAccess{}).Where("group_id = ? AND server = ?", g.ID, "10.0.0.1").Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 group access entry, got %d", count)
	}
}
