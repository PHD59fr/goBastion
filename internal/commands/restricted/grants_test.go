package restricted

import (
	"errors"
	"testing"

	"goBastion/internal/models"
)

func TestGrantAdd_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	_ = newRegularUser(t, db, "alice")

	err := GrantAdd(db, admin, []string{
		"--user", "alice",
		"--command", "realmCreate",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var g models.RestrictedCommandGrant
	if err := db.Where("command = ? AND user_id IN (SELECT id FROM users WHERE username = ?)", "realmCreate", "alice").First(&g).Error; err != nil {
		t.Fatalf("grant not found in DB: %v", err)
	}
}

func TestGrantAdd_PermissionDenied(t *testing.T) {
	db := newTestDB(t)
	regular := newRegularUser(t, db, "regular")

	// The restrictedGrantAdd permission requires admin or super_owner.
	if regular.CanDo(db, "restrictedGrantAdd", "") {
		t.Fatal("expected regular user to lack restrictedGrantAdd permission")
	}
}

func TestGrantDel_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	alice := newRegularUser(t, db, "alice")

	// Seed a grant.
	g := models.RestrictedCommandGrant{
		UserID:      alice.ID,
		Command:     "realmCreate",
		GrantedByID: admin.ID,
	}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	err := GrantDel(db, admin, []string{
		"--user", "alice",
		"--command", "realmCreate",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.RestrictedCommandGrant{}).Where("user_id = ? AND command = ?", alice.ID, "realmCreate").Count(&count)
	if count != 0 {
		t.Fatalf("expected grant to be deleted, count=%d", count)
	}
}

func TestGrantDel_NotFound(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	_ = newRegularUser(t, db, "alice")

	err := GrantDel(db, admin, []string{
		"--user", "alice",
		"--command", "nonexistent",
	})
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestGrantAdd_DuplicateReturnsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	alice := newRegularUser(t, db, "alice")

	g := models.RestrictedCommandGrant{
		UserID:      alice.ID,
		Command:     "realmCreate",
		GrantedByID: admin.ID,
	}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	err := GrantAdd(db, admin, []string{
		"--user", "alice",
		"--command", "realmCreate",
	})
	if err == nil {
		t.Fatal("expected duplicate grant error")
	}
}

func TestGrantList_InvalidArgsReturnError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := GrantList(db, admin, []string{"--invalid"})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestGrantAdd_MissingArgsReturnError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := GrantAdd(db, admin, []string{"--user", "alice"})
	if err == nil || !errors.Is(err, err) {
		t.Fatal("expected missing args error")
	}
}

func TestGrantList_Empty(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := GrantList(db, admin, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGrantList_WithData(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	alice := newRegularUser(t, db, "alice")

	// Seed two grants.
	for _, cmd := range []string{"realmCreate", "realmDelete"} {
		g := models.RestrictedCommandGrant{
			UserID:      alice.ID,
			Command:     cmd,
			GrantedByID: admin.ID,
		}
		if err := db.Create(&g).Error; err != nil {
			t.Fatalf("seed grant %s: %v", cmd, err)
		}
	}

	err := GrantList(db, admin, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.RestrictedCommandGrant{}).Count(&count)
	if count != 2 {
		t.Fatalf("expected 2 grants in DB, got %d", count)
	}
}
