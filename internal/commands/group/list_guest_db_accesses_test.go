package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestListGuestDBAccesses_GuestCanListOwnOnly(t *testing.T) {
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
	if err := db.Create(&models.GroupGuestDBAccess{GroupID: group.ID, UserID: guest.ID, Host: "db1", Port: 5432, Protocol: "postgres", Username: "deploy"}).Error; err != nil {
		t.Fatalf("create guest db access: %v", err)
	}

	if err := ListGuestDBAccesses(db, guest, []string{"--group", "infra", "--account", "bob"}); err != nil {
		t.Fatalf("guest should list own db accesses: %v", err)
	}
	if err := ListGuestDBAccesses(db, guest, []string{"--group", "infra", "--account", "alice"}); err == nil {
		t.Fatal("guest should not list another user's db accesses")
	}
	if err := ListGuestDBAccesses(db, other, []string{"--group", "infra", "--account", "bob"}); err == nil {
		t.Fatal("non-member should not list guest db accesses")
	}
}
