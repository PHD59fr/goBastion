package session

import (
	"context"
	"testing"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/dbConnector"

	"gorm.io/gorm"
)

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
