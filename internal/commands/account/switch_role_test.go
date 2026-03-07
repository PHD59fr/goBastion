package account

import (
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

func TestSwitchSysRoleUser_NotFound(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()

	err := SwitchSysRoleUser(db, mock, "nobody")
	if err == nil {
		t.Fatal("expected error for unknown user, got nil")
	}
}
