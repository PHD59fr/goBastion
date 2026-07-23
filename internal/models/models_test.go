package models

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func newUser(role string, enabled bool) *User {
	return &User{
		ID:       uuid.New(),
		Username: "testuser",
		Role:     role,
		Enabled:  enabled,
	}
}

func TestUser_IsAdmin(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{RoleAdmin, true},
		{RoleUser, false},
		{"", false},
		{"superuser", false},
	}
	for _, tc := range cases {
		u := newUser(tc.role, true)
		if got := u.IsAdmin(); got != tc.want {
			t.Errorf("IsAdmin() with role=%q: got %v, want %v", tc.role, got, tc.want)
		}
	}
}

func TestUser_IsEnabled(t *testing.T) {
	if !newUser(RoleUser, true).IsEnabled() {
		t.Error("expected enabled user to be enabled")
	}
	if newUser(RoleUser, false).IsEnabled() {
		t.Error("expected disabled user to not be enabled")
	}
}

func TestUser_CanDo_NilUser(t *testing.T) {
	var u *User
	if u.CanDo(nil, "accountCreate", "") {
		t.Error("nil user should not be able to do anything")
	}
}

func TestUser_CanDo_AdminCommands(t *testing.T) {
	admin := newUser(RoleAdmin, true)
	regular := newUser(RoleUser, true)

	adminOnly := []string{
		"accountCreate", "accountDelete", "accountModify",
		"accountList", "accountInfo", "accountListIngressKeys",
		"accountAddAccess", "accountDelAccess", "accountListAccess",
		"whoHasAccessTo", "groupCreate", "groupDelete",
	}

	for _, cmd := range adminOnly {
		if !admin.CanDo(nil, cmd, "") {
			t.Errorf("admin should be able to do %q", cmd)
		}
		if regular.CanDo(nil, cmd, "") {
			t.Errorf("regular user should not be able to do %q", cmd)
		}
	}
}

func TestUser_CanDo_TtyCommands(t *testing.T) {
	admin := newUser(RoleAdmin, true)
	regular := newUser(RoleUser, true)

	// ttyList/ttyPlay: admin always allowed; regular user allowed when target=""
	// (user listing their own sessions) but not for another user's sessions.
	for _, cmd := range []string{"ttyList", "ttyPlay"} {
		if !admin.CanDo(nil, cmd, "") {
			t.Errorf("admin should be able to do %q with empty target", cmd)
		}
		if !regular.CanDo(nil, cmd, "") {
			t.Errorf("regular user should be able to do %q with empty target (own sessions)", cmd)
		}
		if regular.CanDo(nil, cmd, "otheruser") {
			t.Errorf("regular user should NOT be able to do %q on another user's sessions", cmd)
		}
		if !regular.CanDo(nil, cmd, regular.Username) {
			t.Errorf("regular user should be able to do %q on their own sessions", cmd)
		}
	}
}

func TestUser_CanDo_SelfCommands(t *testing.T) {
	u := newUser(RoleUser, true)

	selfCmds := []string{
		"selfListIngressKeys", "selfAddIngressKey", "selfDelIngressKey",
		"selfGenerateEgressKey", "selfListEgressKeys",
		"selfListAccesses", "selfAddAccess", "selfDelAccess",
		"selfListAliases", "selfAddAlias", "selfDelAlias",
		"selfRemoveHostFromKnownHosts",
	}

	for _, cmd := range selfCmds {
		if !u.CanDo(nil, cmd, "") {
			t.Errorf("regular user should be able to do self command %q", cmd)
		}
	}
}

func TestUser_CanDo_MiscCommands(t *testing.T) {
	u := newUser(RoleUser, true)

	for _, cmd := range []string{"help", "info", "exit"} {
		if !u.CanDo(nil, cmd, "") {
			t.Errorf("all users should be able to do %q", cmd)
		}
	}
}

func TestUser_CanDo_UnknownCommand(t *testing.T) {
	admin := newUser(RoleAdmin, true)
	if admin.CanDo(nil, "notACommand", "") {
		t.Error("unknown command should not be permitted even for admin")
	}
}

func TestUserGroup_RoleMethods(t *testing.T) {
	cases := []struct {
		role     string
		isOwner  bool
		isGK     bool
		isACL    bool
		isMember bool
		isGuest  bool
	}{
		{"owner", true, false, false, false, false},
		{"gatekeeper", false, true, false, false, false},
		{"aclkeeper", false, false, true, false, false},
		{"member", false, false, false, true, false},
		{"guest", false, false, false, false, true},
		{"", false, false, false, false, false},
	}

	for _, tc := range cases {
		ug := &UserGroup{Role: tc.role}
		if ug.IsOwner() != tc.isOwner {
			t.Errorf("role=%q: IsOwner()=%v, want %v", tc.role, ug.IsOwner(), tc.isOwner)
		}
		if ug.IsGateKeeper() != tc.isGK {
			t.Errorf("role=%q: IsGateKeeper()=%v, want %v", tc.role, ug.IsGateKeeper(), tc.isGK)
		}
		if ug.IsACLKeeper() != tc.isACL {
			t.Errorf("role=%q: IsACLKeeper()=%v, want %v", tc.role, ug.IsACLKeeper(), tc.isACL)
		}
		if ug.IsMember() != tc.isMember {
			t.Errorf("role=%q: IsMember()=%v, want %v", tc.role, ug.IsMember(), tc.isMember)
		}
		if ug.IsGuest() != tc.isGuest {
			t.Errorf("role=%q: IsGuest()=%v, want %v", tc.role, ug.IsGuest(), tc.isGuest)
		}
	}
}

func TestVisibilityPolicies_GroupInfoAndListAll(t *testing.T) {
	defer SetGroupVisibilityMode("open")
	db := newRightsTestDB(t)
	owner, member, outsider, admin, groupName := seedVisibilityTestData(t, db)
	groupViewCmds := []string{
		"groupInfo",
		"groupListAccesses",
		"groupListAliases",
		"groupListDBAccesses",
		"groupListDBAliases",
	}

	SetGroupVisibilityMode("open")
	for _, cmd := range groupViewCmds {
		if !outsider.CanDo(db, cmd, groupName) {
			t.Fatalf("open mode should allow outsider %s", cmd)
		}
	}
	if !outsider.CanListAllGroups(db) {
		t.Fatal("open mode should allow outsider groupList --all")
	}

	SetGroupVisibilityMode("members")
	for _, cmd := range groupViewCmds {
		if outsider.CanDo(db, cmd, groupName) {
			t.Fatalf("members mode should block outsider %s", cmd)
		}
		if !member.CanDo(db, cmd, groupName) {
			t.Fatalf("members mode should allow member %s", cmd)
		}
	}
	if outsider.CanListAllGroups(db) {
		t.Fatal("members mode should block outsider groupList --all")
	}

	SetGroupVisibilityMode("managers")
	for _, cmd := range groupViewCmds {
		if member.CanDo(db, cmd, groupName) {
			t.Fatalf("managers mode should block plain member %s", cmd)
		}
		if !owner.CanDo(db, cmd, groupName) {
			t.Fatalf("managers mode should allow owner %s", cmd)
		}
	}

	SetGroupVisibilityMode("private")
	for _, cmd := range groupViewCmds {
		if outsider.CanDo(db, cmd, groupName) {
			t.Fatalf("private mode should block outsider %s", cmd)
		}
		if !member.CanDo(db, cmd, groupName) {
			t.Fatalf("private mode should still allow direct member %s", cmd)
		}
		if !admin.CanDo(db, cmd, groupName) {
			t.Fatalf("private mode should allow admin %s", cmd)
		}
	}
}

func TestVisibilityPolicies_GroupEgressKeys(t *testing.T) {
	defer SetEgressKeyVisibilityMode("discoverable")
	db := newRightsTestDB(t)
	owner, member, outsider, admin, groupName := seedVisibilityTestData(t, db)

	SetEgressKeyVisibilityMode("discoverable")
	if !outsider.CanDo(db, "groupListEgressKeys", groupName) {
		t.Fatal("discoverable mode should allow outsider egress key listing")
	}

	SetEgressKeyVisibilityMode("members")
	if outsider.CanDo(db, "groupListEgressKeys", groupName) {
		t.Fatal("members mode should block outsider egress key listing")
	}
	if !member.CanDo(db, "groupListEgressKeys", groupName) {
		t.Fatal("members mode should allow member egress key listing")
	}

	SetEgressKeyVisibilityMode("managers")
	if member.CanDo(db, "groupListEgressKeys", groupName) {
		t.Fatal("managers mode should block plain member egress key listing")
	}
	if !owner.CanDo(db, "groupListEgressKeys", groupName) {
		t.Fatal("managers mode should allow owner egress key listing")
	}

	SetEgressKeyVisibilityMode("private")
	if member.CanDo(db, "groupListEgressKeys", groupName) {
		t.Fatal("private mode should block plain member egress key listing")
	}
	if !owner.CanDo(db, "groupListEgressKeys", groupName) {
		t.Fatal("private mode should allow owner egress key listing")
	}
	if !admin.CanDo(db, "groupListEgressKeys", groupName) {
		t.Fatal("private mode should allow admin egress key listing")
	}
}

func TestVisibilityPolicies_GuestGrantLists(t *testing.T) {
	defer SetGroupVisibilityMode("open")
	db := newRightsTestDB(t)
	owner, member, outsider, admin, groupName := seedVisibilityTestData(t, db)
	guest := &User{Username: "guest", Role: RoleUser, Enabled: true}
	if err := db.Create(guest).Error; err != nil {
		t.Fatalf("create guest: %v", err)
	}
	membership := UserGroup{UserID: guest.ID, GroupID: mustGroupID(t, db, groupName), Role: GroupRoleGuest}
	if err := db.Create(&membership).Error; err != nil {
		t.Fatalf("create guest membership: %v", err)
	}

	cmds := []string{"groupListGuestAccesses", "groupListGuestDBAccesses"}

	SetGroupVisibilityMode("open")
	for _, cmd := range cmds {
		if !outsider.CanDo(db, cmd, groupName) {
			t.Fatalf("open mode should allow outsider %s", cmd)
		}
		if !guest.CanInspectGuestGrantTarget(db, groupName, guest.Username) {
			t.Fatalf("guest should be able to inspect own target for %s", cmd)
		}
		if guest.CanInspectGuestGrantTarget(db, groupName, member.Username) {
			t.Fatalf("guest should not be able to inspect another account for %s", cmd)
		}
	}

	SetGroupVisibilityMode("members")
	for _, cmd := range cmds {
		if outsider.CanDo(db, cmd, groupName) {
			t.Fatalf("members mode should block outsider %s", cmd)
		}
		if !member.CanDo(db, cmd, groupName) {
			t.Fatalf("members mode should allow member %s", cmd)
		}
		if !owner.CanDo(db, cmd, groupName) || !admin.CanDo(db, cmd, groupName) {
			t.Fatalf("members mode should allow owner/admin %s", cmd)
		}
	}

	SetGroupVisibilityMode("managers")
	for _, cmd := range cmds {
		if member.CanDo(db, cmd, groupName) {
			t.Fatalf("managers mode should block plain member %s", cmd)
		}
		if guest.CanDo(db, cmd, groupName) {
			t.Fatalf("managers mode should block guest %s", cmd)
		}
		if !owner.CanDo(db, cmd, groupName) {
			t.Fatalf("managers mode should allow owner %s", cmd)
		}
	}
}

func mustGroupID(t *testing.T, db *gorm.DB, groupName string) uuid.UUID {
	t.Helper()
	var group Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		t.Fatalf("find group %s: %v", groupName, err)
	}
	return group.ID
}

func newRightsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &Group{}, &UserGroup{}); err != nil {
		t.Fatalf("migrate rights test DB: %v", err)
	}
	return db
}

func seedVisibilityTestData(t *testing.T, db *gorm.DB) (*User, *User, *User, *User, string) {
	t.Helper()
	group := Group{Name: "infra"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	owner := &User{Username: "owner", Role: RoleUser, Enabled: true}
	member := &User{Username: "member", Role: RoleUser, Enabled: true}
	outsider := &User{Username: "outsider", Role: RoleUser, Enabled: true}
	admin := &User{Username: "admin", Role: RoleAdmin, Enabled: true}
	for _, u := range []*User{owner, member, outsider, admin} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user %s: %v", u.Username, err)
		}
	}

	memberships := []UserGroup{
		{UserID: owner.ID, GroupID: group.ID, Role: GroupRoleOwner},
		{UserID: member.ID, GroupID: group.ID, Role: GroupRoleMember},
	}
	for _, membership := range memberships {
		if err := db.Create(&membership).Error; err != nil {
			t.Fatalf("create membership: %v", err)
		}
	}

	return owner, member, outsider, admin, group.Name
}
