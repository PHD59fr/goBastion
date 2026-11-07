package group

import (
	"sync"
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
	// A duplicate must not create another active group.
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

func TestConcurrentGroupCreateAcrossAdministrators(t *testing.T) {
	db := newTestDB(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	admins := []*models.User{newAdminUser(t, db, "first-admin"), newAdminUser(t, db, "second-admin")}
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() { <-start; results <- Create(db, admins[i%2], []string{"--group", "shared"}) })
	}
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful creates=%d, want 1", success)
	}
	var rows []models.Group
	if err := db.Where("name = ?", "shared").Find(&rows).Error; err != nil || len(rows) != 1 {
		t.Fatalf("active groups=%d, %v", len(rows), err)
	}
	if err := Delete(db, admins[0], []string{"--group", "shared"}); err != nil {
		t.Fatal(err)
	}
	if err := Create(db, admins[1], []string{"--group", "shared"}); err != nil {
		t.Fatal(err)
	}
	var replacement models.Group
	if err := db.Where("name = ?", "shared").First(&replacement).Error; err != nil {
		t.Fatal(err)
	}
	if replacement.ID == rows[0].ID {
		t.Fatal("recreated group inherited the deleted identity")
	}
}
