package models_test

import (
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"

	cmdgroup "goBastion/internal/commands/group"
	"goBastion/internal/commands/realm"
	"goBastion/internal/commands/restricted"
	"goBastion/internal/config"
	bastiondb "goBastion/internal/db"
	"goBastion/internal/models"
	"goBastion/internal/utils/dbConnector"
)

// Run against the disposable metadata databases in the isolation-test image.
func TestCommandLifecycleIntegration(t *testing.T) {
	if os.Getenv("GOB_POLICY_INTEGRATION") != "1" {
		t.Skip("requires database fixtures")
	}
	for _, tc := range []struct{ driver, dsn string }{
		{"postgres", "host=127.0.0.1 port=55432 user=postgres dbname=policytest sslmode=disable"},
		{"mysql", "root@tcp(127.0.0.1:53306)/policytest?parseTime=true"},
	} {
		t.Run(tc.driver, func(t *testing.T) {
			config.ResetForTesting()
			_ = config.Load()
			t.Cleanup(config.ResetForTesting)
			t.Setenv("DB_DRIVER", tc.driver)
			t.Setenv("DB_DSN", tc.dsn)
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			db, err := bastiondb.Init(log, true)
			if err != nil {
				t.Fatal(err)
			}
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sqlDB.Close() }()
			admin := models.User{Username: "lifecycle-admin", Role: models.RoleAdmin, Enabled: true}
			guest := models.User{Username: "lifecycle-guest", Role: models.RoleUser, Enabled: true}
			g := models.Group{Name: "lifecycle-private", MFARequired: true}
			for _, row := range []any{&admin, &guest, &g} {
				if err := db.Create(row).Error; err != nil {
					t.Fatal(err)
				}
			}
			membership := models.UserGroup{UserID: guest.ID, GroupID: g.ID, Role: models.GroupRoleGuest}
			grant := models.GroupGuestDBAccess{UserID: guest.ID, GroupID: g.ID, Host: "db.fixture", Port: 3306, Protocol: "mysql", Username: "reader"}
			for _, row := range []any{&membership, &grant} {
				if err := db.Create(row).Error; err != nil {
					t.Fatal(err)
				}
			}
			if access, err := dbConnector.ResolveTarget(db, guest, "reader@db.fixture:3306:mysql"); err != nil || !access.MFARequired {
				t.Fatalf("bad access fixture: %+v %v", access, err)
			}
			if err := cmdgroup.Delete(db, &admin, []string{"--group", g.Name}); err != nil {
				t.Fatal(err)
			}
			if _, err := dbConnector.ResolveTarget(db, guest, "reader@db.fixture:3306:mysql"); err == nil {
				t.Fatal("deleted group still grants access")
			}
			var count int64
			if err := db.Model(&models.UserGroup{}).Where("group_id = ?", g.ID).Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("membership survived deletion: %d %v", count, err)
			}

			// Different administrators must serialize even on MariaDB, where
			// nullable deleted_at indexes do not enforce active uniqueness.
			otherAdmin := models.User{Username: "lifecycle-second-admin", Role: models.RoleAdmin, Enabled: true}
			if err := db.Create(&otherAdmin).Error; err != nil {
				t.Fatal(err)
			}
			for range 2 {
				results := make(chan error, 8)
				var creators sync.WaitGroup
				ready := make(chan struct{})
				for i := range 8 {
					actor := &admin
					if i%2 == 1 {
						actor = &otherAdmin
					}
					creators.Go(func() { <-ready; results <- cmdgroup.Create(db, actor, []string{"--group", "concurrent-group"}) })
				}
				close(ready)
				creators.Wait()
				close(results)
				successes := 0
				for err := range results {
					if err == nil {
						successes++
					} else {
						t.Logf("concurrent create rejected: %v", err)
					}
				}
				if err := db.Model(&models.Group{}).Where("name = ?", "concurrent-group").Count(&count).Error; err != nil || count != 1 || successes != 1 {
					t.Fatalf("concurrent groups: active=%d successful=%d err=%v", count, successes, err)
				}
				if err := cmdgroup.Delete(db, &admin, []string{"--group", "concurrent-group"}); err != nil {
					t.Fatal(err)
				}
			}

			// Both owners may request removal at once; at least one must survive.
			ownersGroup := models.Group{Name: "concurrent-owners"}
			if err := db.Create(&ownersGroup).Error; err != nil {
				t.Fatal(err)
			}
			for _, actor := range []*models.User{&admin, &otherAdmin} {
				if err := db.Create(&models.UserGroup{UserID: actor.ID, GroupID: ownersGroup.ID, Role: models.GroupRoleOwner}).Error; err != nil {
					t.Fatal(err)
				}
			}
			var removals sync.WaitGroup
			startOwners := make(chan struct{})
			for _, actor := range []*models.User{&admin, &otherAdmin} {
				removals.Go(func() {
					<-startOwners
					_ = cmdgroup.DelMember(db, actor, []string{"--group", ownersGroup.Name, "--user", actor.Username})
				})
			}
			close(startOwners)
			removals.Wait()
			if err := db.Model(&models.UserGroup{}).Where("group_id = ? AND role = ?", ownersGroup.ID, models.GroupRoleOwner).Count(&count).Error; err != nil || count != 1 {
				t.Fatalf("remaining owners=%d err=%v", count, err)
			}

			// Match older manual schemas: nullable deleted_at in the unique index
			// must not permit duplicate active grants during concurrent restores.
			// InnoDB requires an alternative user_id index before replacing the
			// composite index that currently supports its foreign key.
			if err := db.Exec("CREATE INDEX idx_lifecycle_grant_user ON restricted_command_grants (user_id)").Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Migrator().DropIndex(&models.RestrictedCommandGrant{}, "idx_user_command_grant"); err != nil {
				t.Fatal(err)
			}
			if err := db.Exec("CREATE UNIQUE INDEX idx_user_command_grant ON restricted_command_grants (user_id, command, deleted_at)").Error; err != nil {
				t.Fatal(err)
			}
			args := []string{"--user", guest.Username, "--command", "realmCreate"}
			if err := restricted.GrantAdd(db, &admin, args); err != nil {
				t.Fatal(err)
			}
			if err := restricted.GrantDel(db, &admin, args); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			start := make(chan struct{})
			for range 2 {
				wg.Go(func() { <-start; _ = restricted.GrantAdd(db, &admin, args) })
			}
			close(start)
			wg.Wait()
			if err := db.Model(&models.RestrictedCommandGrant{}).Where("user_id = ? AND command = ?", guest.ID, "realmCreate").Count(&count).Error; err != nil || count != 1 {
				t.Fatalf("active grants after concurrent restoration: %d %v", count, err)
			}
			if err := restricted.GrantDel(db, &admin, args); err != nil {
				t.Fatal(err)
			}
			if err := restricted.GrantAdd(db, &admin, args); err != nil {
				t.Fatal(err)
			}

			const publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGT0i7K7nM5j9l9M5HqY9v9M0N4k8m2JQ4VnV8z0V6hK fixture"
			for _, host := range []string{"old.fixture", "new.fixture"} {
				if err := realm.Create(db, &admin, []string{"--realm", "lifecycle-realm", "--bastion", host, "--from", "192.0.2.0/24", "--public-key", publicKey}); err != nil {
					t.Fatal(err)
				}
				if host == "old.fixture" {
					if err := realm.Delete(db, &admin, []string{"--realm", "lifecycle-realm"}); err != nil {
						t.Fatal(err)
					}
				}
			}
			var restored models.Realm
			if err := db.Where("name = ?", "lifecycle-realm").First(&restored).Error; err != nil || restored.BastionHost != "new.fixture" {
				t.Fatalf("wrong restored realm: %+v %v", restored, err)
			}
		})
	}
}
