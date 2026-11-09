package group

import (
	"testing"
	"time"

	"goBastion/internal/models"
)

func TestDelMember_RevokesGuestGrantsInSameTransaction(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	guest := newRegularUser(t, db, "guest")
	other := newRegularUser(t, db, "other")

	group := models.Group{Name: "mygroup"}
	otherGroup := models.Group{Name: "othergroup"}
	for _, g := range []*models.Group{&group, &otherGroup} {
		if err := db.Create(g).Error; err != nil {
			t.Fatalf("create group: %v", err)
		}
	}

	for _, membership := range []models.UserGroup{
		{UserID: guest.ID, GroupID: group.ID, Role: models.GroupRoleGuest},
		{UserID: other.ID, GroupID: group.ID, Role: models.GroupRoleGuest},
		{UserID: guest.ID, GroupID: otherGroup.ID, Role: models.GroupRoleGuest},
	} {
		if err := db.Create(&membership).Error; err != nil {
			t.Fatalf("create membership: %v", err)
		}
	}

	expired := time.Now().Add(-time.Hour)
	grants := []any{
		&models.GroupGuestAccess{UserID: guest.ID, GroupID: group.ID, Server: "host", Port: 22, Username: "remote", Protocol: "ssh", ExpiresAt: &expired},
		&models.GroupGuestDBAccess{UserID: guest.ID, GroupID: group.ID, Host: "db", Port: 5432, Username: "reader", Protocol: "postgres"},
		&models.GroupGuestAccess{UserID: other.ID, GroupID: group.ID, Server: "host", Port: 22, Username: "remote", Protocol: "ssh"},
		&models.GroupGuestAccess{UserID: guest.ID, GroupID: otherGroup.ID, Server: "host", Port: 22, Username: "remote", Protocol: "ssh"},
	}
	for _, grant := range grants {
		if err := db.Create(grant).Error; err != nil {
			t.Fatalf("create guest grant: %v", err)
		}
	}

	if err := DelMember(db, admin, []string{"--group", group.Name, "--user", guest.Username}); err != nil {
		t.Fatalf("DelMember returned error: %v", err)
	}

	for _, model := range []any{&models.GroupGuestAccess{}, &models.GroupGuestDBAccess{}} {
		var active int64
		if err := db.Model(model).Where("user_id = ? AND group_id = ?", guest.ID, group.ID).Count(&active).Error; err != nil {
			t.Fatalf("count active guest grants: %v", err)
		}
		if active != 0 {
			t.Fatalf("%T still has %d active grant(s) after removal", model, active)
		}
		var retained int64
		if err := db.Unscoped().Model(model).Where("user_id = ? AND group_id = ? AND deleted_at IS NOT NULL", guest.ID, group.ID).Count(&retained).Error; err != nil {
			t.Fatalf("count deleted guest grants: %v", err)
		}
		if retained != 1 {
			t.Fatalf("%T soft-deleted grants = %d, want 1", model, retained)
		}
	}

	countActive := func(model any) int64 {
		var count int64
		if err := db.Model(model).Count(&count).Error; err != nil {
			t.Fatalf("count remaining grants: %v", err)
		}
		return count
	}
	if got := countActive(&models.GroupGuestAccess{}); got != 2 {
		t.Fatalf("other guest SSH grants = %d, want 2", got)
	}
	if got := countActive(&models.GroupGuestDBAccess{}); got != 0 {
		t.Fatalf("unrelated guest DB grants = %d, want 0", got)
	}

	if err := AddMember(db, admin, []string{"--group", group.Name, "--user", guest.Username, "--role", models.GroupRoleGuest}); err != nil {
		t.Fatalf("re-add guest: %v", err)
	}
	if got := countActive(&models.GroupGuestAccess{}); got != 2 {
		t.Fatalf("re-adding the guest restored grants: %d active", got)
	}
}

func TestDelMember_PreservesLastOwner(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	owner := newRegularUser(t, db, "owner")
	group := models.Group{Name: "mygroup"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.Create(&models.UserGroup{UserID: owner.ID, GroupID: group.ID, Role: models.GroupRoleOwner}).Error; err != nil {
		t.Fatalf("create owner membership: %v", err)
	}

	if err := DelMember(db, admin, []string{"--group", group.Name, "--user", owner.Username}); err == nil {
		t.Fatal("removing the last owner succeeded")
	}
	var count int64
	if err := db.Model(&models.UserGroup{}).Where("user_id = ? AND group_id = ?", owner.ID, group.ID).Count(&count).Error; err != nil {
		t.Fatalf("count membership: %v", err)
	}
	if count != 1 {
		t.Fatalf("last owner membership was removed")
	}
}

func TestDelMember_Success(t *testing.T) {
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

	err := DelMember(db, admin, []string{
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
