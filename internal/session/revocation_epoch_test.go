package session

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"goBastion/internal/models"
	"gorm.io/gorm"
)

func TestRevocationEpochRejectsReenabledActorBeforeAdmission(t *testing.T) {
	db, actor := admissionPolicyFixture(t)
	authenticated := *actor
	if err := db.Model(actor).Updates(map[string]any{
		"enabled":          false,
		"revocation_epoch": gorm.Expr("revocation_epoch + 1"),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(actor).Update("enabled", true).Error; err != nil {
		t.Fatal(err)
	}
	if err := refreshAuthenticatedUser(db, &authenticated); err == nil {
		t.Fatal("reenabled actor retained an old authentication")
	}
	if release, err := registerActiveSession(db, &models.User{
		ID: authenticated.ID, Username: authenticated.Username, Enabled: true,
		Role: authenticated.Role, RevocationEpoch: 0,
	}, "stale-revision", "ssh"); err == nil {
		release()
		t.Fatal("reenabled actor admitted with old revocation revision")
	}
}

func TestRevocationEpochTerminatesEstablishedDBSessionAfterReenable(t *testing.T) {
	db, _, actor := actorMonitorFixture(t)
	check := dbSessionAuthorizationCheck(actor, "unused", nil, models.DBAccessRight{})
	monitor, ticks, sessionCtx := testDBActorMonitor(t, context.Background(), db, actor, time.Second, check)
	if err := db.Model(&actor).Updates(map[string]any{
		"enabled":          false,
		"revocation_epoch": gorm.Expr("revocation_epoch + 1"),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&actor).Update("enabled", true).Error; err != nil {
		t.Fatal(err)
	}
	ticks <- time.Now()
	awaitActorMonitor(t, monitor.done)
	if !monitor.revoked.Load() || !errors.Is(sessionCtx.Err(), context.Canceled) {
		t.Fatal("reenabled actor's established DB session was not revoked")
	}
}

func TestRevocationEpochTerminatesEstablishedSSHSessionAfterReenable(t *testing.T) {
	const helper = "GOB_TEST_REVOCATION_EPOCH_SSH"
	if os.Getenv(helper) == "1" {
		db, _, actor := actorMonitorFixture(t)
		startSessionActorMonitor(context.Background(), db, actor.ID, "", actor, nil)
		if err := db.Model(&actor).Updates(map[string]any{
			"enabled":          false,
			"revocation_epoch": gorm.Expr("revocation_epoch + 1"),
		}).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Model(&actor).Update("enabled", true).Error; err != nil {
			t.Fatal(err)
		}
		<-time.After(3 * time.Second)
		os.Exit(42)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRevocationEpochTerminatesEstablishedSSHSessionAfterReenable$")
	cmd.Env = append(os.Environ(), helper+"=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("SSH monitor did not stop: %v; output: %s", ctx.Err(), output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("SSH monitor retained revoked session: %v; output: %s", err, output)
	}
}
