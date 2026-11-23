package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/dbConnector"

	"gorm.io/gorm"
)

func TestDBSessionAuthorizationRevokesConcurrentGrantChange(t *testing.T) {
	for _, change := range []string{"delete", "password rotation", "group membership", "lookup failure"} {
		t.Run(change, func(t *testing.T) {
			db, _, actor := actorMonitorFixture(t)
			if err := db.AutoMigrate(&models.Group{}, &models.UserGroup{}, &models.SelfDBAccess{}, &models.GroupDBAccess{}, &models.GroupGuestDBAccess{}); err != nil {
				t.Fatal(err)
			}
			grant := models.SelfDBAccess{UserID: actor.ID, Host: "db.example", Port: 5432, Protocol: "postgres", Username: "reader", Password: encryptedFixture(t, "original-password")}
			membership := models.UserGroup{UserID: actor.ID, Role: models.GroupRoleMember}
			if change == "group membership" {
				group := models.Group{Name: "operators"}
				if err := db.Create(&group).Error; err != nil {
					t.Fatal(err)
				}
				membership.GroupID = group.ID
				if err := db.Create(&membership).Error; err != nil {
					t.Fatal(err)
				}
				if err := db.Create(&models.GroupDBAccess{GroupID: group.ID, Host: grant.Host, Port: grant.Port, Protocol: grant.Protocol, Username: grant.Username, Password: grant.Password}).Error; err != nil {
					t.Fatal(err)
				}
			} else if err := db.Create(&grant).Error; err != nil {
				t.Fatal(err)
			}
			target := "reader@db.example:5432:postgres"
			admitted, err := dbConnector.ResolveTarget(db, actor, target)
			if err != nil {
				t.Fatal(err)
			}

			// Pause the monitor after a successful actor lookup. The policy
			// change commits while that polling iteration is still in flight,
			// before it revalidates the selected target grant.
			actorLoaded := make(chan struct{})
			continueAuthorization := make(chan struct{})
			var actorQueryCtx context.Context
			var pause, release sync.Once
			if err := db.Callback().Query().After("gorm:query").Register("test:concurrent_grant_change", func(tx *gorm.DB) {
				fresh, ok := tx.Statement.Dest.(*models.User)
				if !ok || fresh.ID != actor.ID {
					return
				}
				pause.Do(func() {
					actorQueryCtx = tx.Statement.Context
					close(actorLoaded)
					select {
					case <-continueAuthorization:
					case <-tx.Statement.Context.Done():
					}
				})
			}); err != nil {
				t.Fatal(err)
			}
			monitor, ticks, sessionCtx := testDBActorMonitor(t, context.Background(), db, actor, time.Second, dbSessionAuthorizationCheck(actor, target, nil, admitted))
			t.Cleanup(func() { release.Do(func() { close(continueAuthorization) }) })
			ticks <- time.Now()
			awaitActorMonitor(t, actorLoaded)
			switch change {
			case "delete":
				err = db.Delete(&grant).Error
			case "password rotation":
				err = db.Model(&grant).Update("password", encryptedFixture(t, "rotated-password")).Error
			case "group membership":
				err = db.Delete(&membership).Error
			case "lookup failure":
				err = db.Migrator().DropTable(&models.SelfDBAccess{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := actorQueryCtx.Err(); err != nil {
				t.Fatalf("policy change did not finish within the healthy actor lookup deadline: %v", err)
			}
			release.Do(func() { close(continueAuthorization) })
			awaitActorMonitor(t, monitor.done)
			if !monitor.revoked.Load() || !errors.Is(sessionCtx.Err(), context.Canceled) {
				t.Fatal("concurrent grant change did not cancel the database session")
			}
			if err := monitor.finish(sessionCtx, nil); !errors.Is(err, errDBActorRevoked) {
				t.Fatalf("connector success bypassed concurrent grant change: %v", err)
			}
		})
	}
}

func TestDBSessionAuthorizationRevalidatesSelectedGrant(t *testing.T) {
	for _, change := range []string{"delete", "expire", "cidr", "role", "group membership", "group policy"} {
		t.Run(change, func(t *testing.T) {
			db, _, actor := actorMonitorFixture(t)
			if err := db.AutoMigrate(&models.Group{}, &models.UserGroup{}, &models.SelfDBAccess{}, &models.GroupDBAccess{}, &models.GroupGuestDBAccess{}); err != nil {
				t.Fatal(err)
			}
			grant := models.SelfDBAccess{UserID: actor.ID, Host: "db.example", Port: 5432, Protocol: "postgres", Username: "reader"}
			group := models.Group{Name: "operators"}
			membership := models.UserGroup{UserID: actor.ID, Role: models.GroupRoleMember}
			groupGrant := models.GroupDBAccess{Host: grant.Host, Port: grant.Port, Protocol: grant.Protocol, Username: grant.Username}
			isGroup := change == "group membership" || change == "group policy"
			if isGroup {
				if err := db.Create(&group).Error; err != nil {
					t.Fatal(err)
				}
				membership.GroupID = group.ID
				groupGrant.GroupID = group.ID
				if err := db.Create(&membership).Error; err != nil {
					t.Fatal(err)
				}
				if err := db.Create(&groupGrant).Error; err != nil {
					t.Fatal(err)
				}
			} else if err := db.Create(&grant).Error; err != nil {
				t.Fatal(err)
			}
			target := "reader@db.example:5432:postgres"
			admitted, err := dbConnector.ResolveTarget(db, actor, target)
			if err != nil {
				t.Fatal(err)
			}
			check := dbSessionAuthorizationCheck(actor, target, nil, admitted)
			if err := check(t.Context(), db, actor); err != nil {
				t.Fatalf("healthy grant: %v", err)
			}
			switch change {
			case "delete":
				err = db.Delete(&grant).Error
			case "expire":
				err = db.Model(&grant).Update("expires_at", time.Now().Add(-time.Second)).Error
			case "cidr":
				err = db.Model(&grant).Update("allowed_from", "192.0.2.0/24").Error
			case "role":
				actor.Role = models.RoleAdmin
			case "group membership":
				err = db.Delete(&membership).Error
			case "group policy":
				err = db.Model(&group).Update("mfa_required", true).Error
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := check(t.Context(), db, actor); err == nil {
				t.Fatal("changed authorization remained usable")
			}
		})
	}
}

func TestDBSessionAuthorizationTimeoutRevokesMonitor(t *testing.T) {
	db, _, actor := actorMonitorFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sessionCtx, revoke := context.WithCancel(t.Context())
	defer revoke()
	monitor := &dbActorMonitor{cancel: cancel, done: make(chan struct{})}
	monitor.checkAuthorization = func(ctx context.Context, _ *gorm.DB, _ models.User) error {
		<-ctx.Done()
		return ctx.Err()
	}
	ticks := make(chan time.Time, 1)
	go func() { defer close(monitor.done); monitor.run(ctx, db, actor.ID, ticks, 25*time.Millisecond, revoke) }()
	ticks <- time.Now()
	awaitActorMonitor(t, monitor.done)
	if !monitor.revoked.Load() || sessionCtx.Err() == nil {
		t.Fatal("authorization timeout did not cancel session")
	}
	monitor.stop()
}
