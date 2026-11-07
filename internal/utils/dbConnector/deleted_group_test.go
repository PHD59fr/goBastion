package dbConnector

import (
	"testing"

	cmdgroup "goBastion/internal/commands/group"
	"goBastion/internal/config"
	"goBastion/internal/models"
)

func TestDeletedGroupRevokesGuestDatabase(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "command deletion", true: "legacy orphaned rows"}[legacy], func(t *testing.T) {
			db := newAliasTestDB(t)
			if err := db.AutoMigrate(&models.GroupAccess{}, &models.GroupGuestAccess{}, &models.GroupEgressKey{}, &models.Aliases{}); err != nil {
				t.Fatal(err)
			}
			u := models.User{Username: "guest", Role: models.RoleUser, Enabled: true}
			admin := models.User{Username: "admin", Role: models.RoleAdmin, Enabled: true}
			g := models.Group{Name: "private", MFARequired: true}
			for _, row := range []any{&u, &admin, &g} {
				if err := db.Create(row).Error; err != nil {
					t.Fatal(err)
				}
			}
			member := models.UserGroup{UserID: u.ID, GroupID: g.ID, Role: models.GroupRoleGuest}
			grant := models.GroupGuestDBAccess{UserID: u.ID, GroupID: g.ID, Username: "reader", Host: "fixture.example", Port: 3306, Protocol: "mysql", Password: "fixture-password"}
			for _, row := range []any{&member, &grant} {
				if err := db.Create(row).Error; err != nil {
					t.Fatal(err)
				}
			}
			before, err := ResolveTarget(db, u, "reader@fixture.example:3306:mysql")
			if err != nil || !before.MFARequired {
				t.Fatalf("bad fixture: %v %+v", err, before)
			}
			if legacy {
				if err := db.Delete(&g).Error; err != nil {
					t.Fatal(err)
				}
			} else {
				if err := cmdgroup.Delete(db, &admin, []string{"--group", "private"}); err != nil {
					t.Fatal(err)
				}
			}
			after, err := ResolveTarget(db, u, "reader@fixture.example:3306:mysql")
			if err == nil {
				t.Errorf("deleted group still grants DB access, MFARequired=%t source=%q", after.MFARequired, after.Source)
			}

		})
	}
}
