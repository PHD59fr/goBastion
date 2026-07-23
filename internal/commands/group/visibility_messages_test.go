package group

import (
	"strings"
	"testing"

	"goBastion/internal/models"
)

func TestGroupListAllDeniedMessageIncludesCurrentPolicy(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	models.SetGroupVisibilityMode("members")
	defer models.SetGroupVisibilityMode("open")

	out := captureStdout(t, func() {
		_ = List(db, user, []string{"--all"})
	})

	for _, want := range []string{
		"You do not have permission to list all groups under the current visibility policy.",
		"Current policy: security.group_visibility.mode=members",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestGroupInfoDeniedMessageIncludesRequiredRoleHint(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	group := models.Group{Name: "infra"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	models.SetGroupVisibilityMode("managers")
	defer models.SetGroupVisibilityMode("open")

	out := captureStdout(t, func() {
		_ = Info(db, user, []string{"--group", "infra"})
	})

	for _, want := range []string{
		"You do not have permission to view group 'infra' under the current visibility policy.",
		"Current policy: security.group_visibility.mode=managers",
		"Required: owner, aclkeeper, gatekeeper, admin, or superowner in the target group.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestGroupListEgressKeysDeniedMessageIncludesPrivatePolicyHint(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	group := models.Group{Name: "infra"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	models.SetEgressKeyVisibilityMode("private")
	defer models.SetEgressKeyVisibilityMode("discoverable")

	out := captureStdout(t, func() {
		_ = ListEgressKeys(db, user, []string{"--group", "infra"})
	})

	for _, want := range []string{
		"You do not have permission to list egress keys for group 'infra'.",
		"Current policy: security.egress_key_visibility.mode=private",
		"Required: group owner, admin, or superowner.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestGuestOwnOnlyDeniedMessageIncludesRequestedAccount(t *testing.T) {
	db := newTestDB(t)
	group := models.Group{Name: "infra"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	guest := newRegularUser(t, db, "bob")
	if err := db.Create(&models.UserGroup{UserID: guest.ID, GroupID: group.ID, Role: models.GroupRoleGuest}).Error; err != nil {
		t.Fatalf("create guest membership: %v", err)
	}

	out := captureStdout(t, func() {
		_ = ListGuestAccesses(db, guest, []string{"--group", "infra", "--account", "alice"})
	})

	for _, want := range []string{
		"Guest users can only view their own grants in this group.",
		"Requested account: alice",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}
