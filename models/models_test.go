package models

import (
	"testing"

	"github.com/google/uuid"
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
		role      string
		isOwner   bool
		isGK      bool
		isACL     bool
		isMember  bool
		isGuest   bool
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
