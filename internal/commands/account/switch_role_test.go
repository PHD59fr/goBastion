package account

import (
	"strings"
	"testing"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

func TestSwitchSysRoleUser_UserToAdmin(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	newRegularUser(t, db, "dave")

	if err := SwitchSysRoleUser(db, mock, "dave"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var u models.User
	db.Where("username = ?", "dave").First(&u)
	if u.Role != models.RoleAdmin {
		t.Fatalf("expected role=admin, got %s", u.Role)
	}
	if len(mock.UpdatedSudoers) == 0 {
		t.Fatal("expected mock.UpdatedSudoers to be non-empty")
	}
}

func TestSwitchSysRoleUser_AdminToUser(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	// Create a second admin so that demoting "eve" is allowed.
	newAdminUser(t, db, "other_admin")
	newAdminUser(t, db, "eve")

	if err := SwitchSysRoleUser(db, mock, "eve"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var u models.User
	db.Where("username = ?", "eve").First(&u)
	if u.Role != models.RoleUser {
		t.Fatalf("expected role=user, got %s", u.Role)
	}
}

func TestSwitchSysRoleUser_LastAdminDemotionBlocked(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	newAdminUser(t, db, "sole_admin")

	err := SwitchSysRoleUser(db, mock, "sole_admin")
	if err == nil {
		t.Fatal("expected error when demoting the last admin, got nil")
	}
	if !strings.Contains(err.Error(), "last remaining admin") {
		t.Fatalf("expected 'last remaining admin' error, got: %v", err)
	}
}

func TestSwitchSysRoleUser_NotFound(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()

	err := SwitchSysRoleUser(db, mock, "nobody")
	if err == nil {
		t.Fatal("expected error for unknown user, got nil")
	}
}
