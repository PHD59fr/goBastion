package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestCreate_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := Create(db, admin, []string{"--group", "mygroup"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var g models.Group
	if err := db.Where("name = ?", "mygroup").First(&g).Error; err != nil {
		t.Fatalf("group not found in DB: %v", err)
	}
}

func TestCreate_Duplicate(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	if err := Create(db, admin, []string{"--group", "mygroup"}); err != nil {
		t.Fatalf("unexpected error on first create: %v", err)
	}
	// Second create returns nil (group already exists, no error, no duplicate)
	_ = Create(db, admin, []string{"--group", "mygroup"})

	var count int64
	db.Model(&models.Group{}).Where("name = ?", "mygroup").Count(&count)
	if count != 1 {
		t.Fatalf("expected exactly 1 group, got %d", count)
	}
}

func TestCreate_AccessDenied(t *testing.T) {
	db := newTestDB(t)
	regular := newRegularUser(t, db, "regularuser")

	err := Create(db, regular, []string{"--group", "mygroup"})
	if err == nil {
		t.Fatal("expected access denied error for regular user, got nil")
	}
}
