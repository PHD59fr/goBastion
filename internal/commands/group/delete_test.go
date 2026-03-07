package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestGroupDelete_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Create group first
	g := models.Group{Name: "todelete"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	err := GroupDelete(db, admin, []string{"--group", "todelete"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.Group{}).Where("name = ?", "todelete").Count(&count)
	if count != 0 {
		t.Fatalf("expected group to be soft-deleted, count=%d", count)
	}
}

func TestGroupDelete_NotFound(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Deleting non-existent group should not return error (GORM soft-delete on 0 rows)
	_ = GroupDelete(db, admin, []string{"--group", "nonexistent"})
}
