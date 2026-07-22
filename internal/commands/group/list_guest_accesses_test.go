package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestListGuestAccesses_GuestCanListOwnOnly(t *testing.T) {
	db := newTestDB(t)
	group := models.Group{Name: "infra"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	guest := newRegularUser(t, db, "bob")
	other := newRegularUser(t, db, "alice")
	if err := db.Create(&models.UserGroup{UserID: guest.ID, GroupID: group.ID, Role: models.GroupRoleGuest}).Error; err != nil {
		t.Fatalf("create guest membership: %v", err)
	}
	if err := db.Create(&models.GroupGuestAccess{GroupID: group.ID, UserID: guest.ID, Server: "srv1", Port: 22, Username: "deploy"}).Error; err != nil {
		t.Fatalf("create guest access: %v", err)
	}

	if err := ListGuestAccesses(db, guest, []string{"--group", "infra", "--account", "bob"}); err != nil {
		t.Fatalf("guest should list own accesses: %v", err)
	}
	if err := ListGuestAccesses(db, guest, []string{"--group", "infra", "--account", "alice"}); err == nil {
		t.Fatal("guest should not list another user's accesses")
	}
	if err := ListGuestAccesses(db, other, []string{"--group", "infra", "--account", "bob"}); err == nil {
		t.Fatal("non-member should not list guest accesses")
	}
}
