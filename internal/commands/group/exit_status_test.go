package group

import (
	"io"
	"log/slog"
	"testing"

	"goBastion/internal/models"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestInvalidGroupCommandsReturnErrorsWithoutMutation(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	group := models.Group{Name: "mygroup"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"set MFA without arguments", func() error {
			return SetMFA(db, admin, testLogger(), nil)
		}},
		{"set MFA without policy", func() error {
			return SetMFA(db, admin, testLogger(), []string{"--group", group.Name})
		}},
		{"add guest DB access without arguments", func() error {
			return AddGuestDBAccess(db, admin, nil)
		}},
		{"delete DB alias without arguments", func() error {
			return DelDBAlias(db, admin, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil {
				t.Fatal("command returned nil after displaying an error")
			}
		})
	}

	var reloaded models.Group
	if err := db.First(&reloaded, "id = ?", group.ID).Error; err != nil {
		t.Fatalf("reload group: %v", err)
	}
	if reloaded.MFARequired {
		t.Fatal("failed MFA command mutated the group")
	}
	var grants int64
	if err := db.Model(&models.GroupGuestDBAccess{}).Count(&grants).Error; err != nil {
		t.Fatalf("count guest DB grants: %v", err)
	}
	if grants != 0 {
		t.Fatalf("failed guest DB command created %d grant(s)", grants)
	}
}

func TestSetMFAAuthorizationFailureReturnsErrorWithoutMutation(t *testing.T) {
	db := newTestDB(t)
	member := newRegularUser(t, db, "member")
	group := models.Group{Name: "mygroup"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.Create(&models.UserGroup{UserID: member.ID, GroupID: group.ID, Role: models.GroupRoleMember}).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}

	if err := SetMFA(db, member, testLogger(), []string{"--group", group.Name, "--required"}); err == nil {
		t.Fatal("unauthorized MFA change returned nil")
	}
	var reloaded models.Group
	if err := db.First(&reloaded, "id = ?", group.ID).Error; err != nil {
		t.Fatalf("reload group: %v", err)
	}
	if reloaded.MFARequired {
		t.Fatal("unauthorized MFA change was applied")
	}
}

func TestAddGuestDBAccessRejectsNonGuestWithoutMutation(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	member := newRegularUser(t, db, "member")
	group := models.Group{Name: "mygroup"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.Create(&models.UserGroup{UserID: member.ID, GroupID: group.ID, Role: models.GroupRoleMember}).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}

	err := AddGuestDBAccess(db, admin, []string{
		"--group", group.Name,
		"--account", member.Username,
		"--host", "db.internal",
		"--user", "reader",
		"--protocol", "postgres",
	})
	if err == nil {
		t.Fatal("non-guest grant returned nil")
	}
	var grants int64
	if err := db.Model(&models.GroupGuestDBAccess{}).Count(&grants).Error; err != nil {
		t.Fatalf("count guest DB grants: %v", err)
	}
	if grants != 0 {
		t.Fatalf("non-guest grant created %d row(s)", grants)
	}
}
