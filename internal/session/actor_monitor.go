package session

import (
	"context"
	"log/slog"
	"os"
	"time"

	"goBastion/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type actorAuthState struct {
	enabled      bool
	systemUser   bool
	role         string
	oshOnly      bool
	superOwner   bool
	passwordHash string
	totpEnabled  bool
	totpSecret   string
}

const sessionRevocationCleanupTimeout = 2 * time.Second

func snapshotActorAuthState(u *models.User) actorAuthState {
	if u == nil {
		return actorAuthState{}
	}
	return actorAuthState{
		enabled:      u.Enabled,
		systemUser:   u.SystemUser,
		role:         u.Role,
		oshOnly:      u.OSHOnly,
		superOwner:   u.SuperOwner,
		passwordHash: u.PasswordHash,
		totpEnabled:  u.TOTPEnabled,
		totpSecret:   u.TOTPSecret,
	}
}

func (s actorAuthState) revokedAgainst(fresh models.User) bool {
	if !fresh.Enabled || fresh.SystemUser {
		return true
	}
	if s.enabled != fresh.Enabled || s.systemUser != fresh.SystemUser || s.role != fresh.Role || s.oshOnly != fresh.OSHOnly || s.superOwner != fresh.SuperOwner {
		return true
	}
	if s.passwordHash != fresh.PasswordHash || s.totpEnabled != fresh.TOTPEnabled || s.totpSecret != fresh.TOTPSecret {
		return true
	}
	return false
}

// terminateRevokedSession performs a bounded, best-effort session-registry
// cleanup and then terminates the process. The cleanup runs in a separate
// goroutine so a stalled database call cannot suppress termination, and the
// caller waits at most timeout before exiting and closing the SSH transport.
func terminateRevokedSession(db *gorm.DB, sessionID string, log *slog.Logger, timeout time.Duration, exit func(int)) {
	if sessionID != "" {
		done := make(chan struct{})
		go func() {
			defer close(done)
			cleanupCtx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_ = db.WithContext(cleanupCtx).Where("session_id = ?", sessionID).Delete(&models.ActiveSession{}).Error
		}()
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			if log != nil {
				log.Warn("session_revocation_cleanup_timeout", slog.String("reason", "session registry cleanup exceeded its deadline"))
			}
		}
	}
	exit(1)
}

// startSessionActorMonitor enforces local revocation for the session lifetime.
// It polls the actor's authorization-relevant state and terminates the process
// if the account is no longer authorized or its authenticated factors changed.
// This is a best-effort local control; it does not provide distributed
// revocation guarantees.
func startSessionActorMonitor(ctx context.Context, db *gorm.DB, actorID uuid.UUID, sessionID string, initial models.User, log *slog.Logger) (stop func()) {
	baseline := snapshotActorAuthState(&initial)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				queryCtx, qcancel := context.WithTimeout(ctx, time.Second)
				var fresh models.User
				err := db.WithContext(queryCtx).First(&fresh, "id = ?", actorID).Error
				qcancel()
				if ctx.Err() != nil {
					return
				}
				if err != nil || baseline.revokedAgainst(fresh) {
					reason := "account disabled or unavailable"
					if err == nil {
						reason = "account authorization changed"
					}
					if log != nil {
						log.Warn("session_revoked", slog.String("reason", reason))
					}
					// Best-effort cleanup of the local session registration before
					// forced termination. Process-exit cleanup may not run, but this
					// cleanup must never delay termination: a stalled database or
					// saturated pool is bounded and process exit closes the transport.
					terminateRevokedSession(db, sessionID, log, sessionRevocationCleanupTimeout, os.Exit)
					return
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
