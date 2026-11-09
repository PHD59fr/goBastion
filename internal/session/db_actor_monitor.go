package session

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"goBastion/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	dbActorPollInterval = time.Second
	dbActorQueryTimeout = time.Second
)

var errDBActorRevoked = errors.New("database session authorization revoked")

// dbActorMonitor checks the actor's continued existence and enabled state. It
// does not refresh target grants or provide distributed admission guarantees.
type dbActorMonitor struct {
	cancel  context.CancelFunc
	done    chan struct{}
	revoked atomic.Bool
}

func startDBActorMonitor(parent context.Context, db *gorm.DB, actorID uuid.UUID, revoke context.CancelFunc) *dbActorMonitor {
	ctx, cancel := context.WithCancel(parent)
	monitor := &dbActorMonitor{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(monitor.done)
		ticker := time.NewTicker(dbActorPollInterval)
		defer ticker.Stop()
		monitor.run(ctx, db, actorID, ticker.C, dbActorQueryTimeout, revoke)
	}()
	return monitor
}

// stop cancels an in-flight lookup and waits for the worker before admission
// registration is released. The database driver must honor query contexts.
func (m *dbActorMonitor) stop() {
	m.cancel()
	<-m.done
}

// finish retains a failed authorization decision even when the connector treats
// the recorder's cancellation exit as successful completion.
func (m *dbActorMonitor) finish(ctx context.Context, sessionErr error) error {
	m.stop()
	if sessionErr != nil {
		return sessionErr
	}
	if m.revoked.Load() {
		return errDBActorRevoked
	}
	return ctx.Err()
}

func (m *dbActorMonitor) run(ctx context.Context, db *gorm.DB, actorID uuid.UUID, ticks <-chan time.Time, queryTimeout time.Duration, revoke context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
			var fresh models.User
			err := db.WithContext(queryCtx).First(&fresh, "id = ?", actorID).Error
			if err == nil {
				err = queryCtx.Err()
			}
			cancel()
			// Session teardown also cancels pending queries; it is not an
			// account revocation and must not be logged as one.
			if ctx.Err() != nil {
				return
			}
			if err != nil || !fresh.Enabled || fresh.SystemUser {
				m.revoked.Store(true)
				revoke()
				return
			}
		}
	}
}
