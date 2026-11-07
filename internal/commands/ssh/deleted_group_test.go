package ssh

import (
	"log/slog"
	"testing"

	cmdgroup "goBastion/internal/commands/group"
	"goBastion/internal/config"
	"goBastion/internal/models"
)

func TestDeletedGroupRevokesSSHAndTCP(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "command deletion", true: "legacy orphaned rows"}[legacy], func(t *testing.T) {
			db := newTestDB(t)
			if err := db.AutoMigrate(&models.GroupDBAccess{}, &models.GroupGuestDBAccess{}, &models.DatabaseAlias{}); err != nil {
				t.Fatal(err)
			}
			u := mustCreateUser(t, db, "member", models.RoleUser)
			admin := mustCreateUser(t, db, "admin", models.RoleAdmin)
			g := mustCreateGroup(t, db, "private")
			if err := db.Model(&g).Update("mfa_required", true).Error; err != nil {
				t.Fatal(err)
			}
			mustAddUserToGroup(t, db, u.ID, g.ID, models.GroupRoleMember)
			mustCreateGroupAccess(t, db, g.ID, "deploy", "fixture.example", 22)
			mustCreateGroupEgressKey(t, db, g.ID)
			before, err := accessFilter(db, u, "deploy", "fixture.example", "22", "ssh")
			if err != nil || len(before) != 1 || !before[0].MFARequired {
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
			for _, protocol := range []string{"ssh", "sftp", "scpupload", "rsync"} {
				after, err := accessFilter(db, u, "deploy", "fixture.example", "22", protocol)
				if err == nil && len(after) > 0 {
					t.Errorf("deleted group still grants %s, MFARequired=%t source=%q", protocol, after[0].MFARequired, after[0].Source)
				}
			}
			access, err := tcpProxyAccessFilter(db, slog.Default(), u, "fixture.example", 22)
			if err == nil {
				t.Errorf("deleted group still grants TCP proxy, MFARequired=%t source=%q", access.MFARequired, access.Source)
			}

		})
	}
}
