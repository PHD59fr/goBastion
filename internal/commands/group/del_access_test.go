package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestGroupDelAccess_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	g := models.Group{Name: "mygroup"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	access := models.GroupAccess{
		GroupID:  g.ID,
		Server:   "10.0.0.1",
		Port:     22,
		Username: "deploy",
		Protocol: "ssh",
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatalf("create group access: %v", err)
	}

	err := GroupDelAccess(db, admin, []string{
		"--group", "mygroup",
		"--access", access.ID.String(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.GroupAccess{}).Where("id = ?", access.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected group access to be deleted, count=%d", count)
	}
}
