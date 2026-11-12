package session

import (
	"context"
	"errors"

	"goBastion/internal/models"
	"goBastion/internal/utils/dbConnector"

	"gorm.io/gorm"
)

// Re-resolve the same request against shared policy rather than retaining a
// grant for the lifetime of the client. ResolveTargetDetailed enforces grant
// expiry, membership, CIDR and group MFA requirements. Any policy or credential
// change to the selected grant requires a new authenticated connection.
func dbSessionAuthorizationCheck(initial models.User, target string, args []string, admitted models.DBAccessRight) func(context.Context, *gorm.DB, models.User) error {
	baseline := snapshotActorAuthState(&initial)
	requestArgs := append([]string(nil), args...)
	return func(ctx context.Context, db *gorm.DB, fresh models.User) error {
		if baseline.revokedAgainst(fresh) {
			return errDBActorRevoked
		}
		resolved, _, err := dbConnector.ResolveTargetDetailed(db.WithContext(ctx), fresh, target, requestArgs...)
		if err != nil {
			// Do not expose resolver diagnostics containing target configuration.
			return errDBActorRevoked
		}
		if resolved != admitted {
			return errors.New("database session target authorization changed")
		}
		return ctx.Err()
	}
}
