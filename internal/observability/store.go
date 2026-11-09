// Package observability provides bounded metrics shared by independent bastion
// processes. Observation failures must be audited by callers, never substituted
// with an authentication or authorization success.
package observability

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"goBastion/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

const (
	SessionsTotal                  = "gobastion_sessions_total"
	AccessDeniedTotal              = "gobastion_access_denied_total"
	AuthFailuresTotal              = "gobastion_auth_failures_total"
	MFAFailuresTotal               = "gobastion_mfa_failures_total"
	SyncFailuresTotal              = "gobastion_sync_failures_total"
	DBConnectionErrorsTotal        = "gobastion_db_connection_errors_total"
	RecordingArchivalFailuresTotal = "gobastion_recording_archival_failures_total"
	RealmAuthFailuresTotal         = "gobastion_realm_auth_failures_total"
	syncCount                      = "gobastion_sync_duration_seconds_count"
	syncNanoseconds                = "gobastion_sync_duration_nanoseconds_sum"
	recordTimeout                  = 500 * time.Millisecond
)

var counterNames = []string{SessionsTotal, AccessDeniedTotal, AuthFailuresTotal, MFAFailuresTotal, SyncFailuresTotal, DBConnectionErrorsTotal, RecordingArchivalFailuresTotal, RealmAuthFailuresTotal}
var (
	ErrInvalidObservation = errors.New("invalid observation metric or delta")
	ErrObservationWrite   = errors.New("observation persistence failed")
	ErrObservationRead    = errors.New("observation collection failed")
)

type Store struct {
	db         *gorm.DB
	instanceID string
}

// NewStore never migrates schemas. Root bootstrap must register ObservationCounter
// before sessions start; ForceCommand processes only update existing rows.
func NewStore(db *gorm.DB, instanceID string) (*Store, error) {
	if db == nil || len(instanceID) == 0 || len(instanceID) > 191 || strings.ContainsAny(instanceID, "\x00\r\n") {
		return nil, errors.New("invalid observation store configuration")
	}
	return &Store{db: db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}), instanceID: instanceID}, nil
}

// Record adds a positive delta to a fixed counter using one atomic upsert. The
// DB is shared across processes; no exporter-local counters pretend to track
// events from other sessions. Values saturate at MaxInt64 rather than wrap.
func (s *Store) Record(ctx context.Context, name string, delta int64) error {
	if !isCounter(name) || delta <= 0 {
		return ErrInvalidObservation
	}
	ctx, cancel := boundedRecordContext(ctx)
	defer cancel()
	if s == nil || s.db == nil || s.add(ctx, s.db, name, delta) != nil {
		return ErrObservationWrite
	}
	return nil
}

// ObserveSyncDuration records count and elapsed nanoseconds atomically. Its
// exposition is a Prometheus summary with count/sum and no quantile estimates.
func (s *Store) ObserveSyncDuration(ctx context.Context, duration time.Duration) error {
	if duration < 0 {
		return ErrInvalidObservation
	}
	ctx, cancel := boundedRecordContext(ctx)
	defer cancel()
	if s == nil || s.db == nil {
		return ErrObservationWrite
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.add(ctx, tx, syncCount, 1); err != nil {
			return err
		}
		return s.add(ctx, tx, syncNanoseconds, int64(duration))
	})
	if err != nil {
		return ErrObservationWrite
	}
	return nil
}

func boundedRecordContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, recordTimeout)
}

func isCounter(name string) bool {
	for _, allowed := range counterNames {
		if name == allowed {
			return true
		}
	}
	return false
}

func (s *Store) add(ctx context.Context, db *gorm.DB, name string, delta int64) error {
	column := clause.Column{Table: "observation_counters", Name: "value"}
	increment := gorm.Expr("CASE WHEN ? > ? THEN ? ELSE ? + ? END", column, int64(math.MaxInt64)-delta, int64(math.MaxInt64), column, delta)
	row := models.ObservationCounter{InstanceID: s.instanceID, Name: name, Value: delta, UpdatedAt: time.Now().UTC()}
	return db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "instance_id"}, {Name: "name"}},
		DoUpdates: clause.Assignments(map[string]any{"value": increment, "updated_at": row.UpdatedAt}),
	}).Create(&row).Error
}

type Snapshot struct {
	Counters        map[string]int64
	ActiveSessions  int64
	SyncCount       int64
	SyncNanoseconds int64
}

// Snapshot scopes both durable counters and registry entries to this exporter
// instance. Registry entries are not process-liveness proofs; stale entries can
// remain until the existing session-registry cleanup runs.
func (s *Store) Snapshot(ctx context.Context) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result := Snapshot{Counters: make(map[string]int64, len(counterNames))}
	if s == nil || s.db == nil {
		return result, ErrObservationRead
	}
	for _, name := range counterNames {
		result.Counters[name] = 0
	}
	names := append(append([]string{}, counterNames...), syncCount, syncNanoseconds)
	var rows []models.ObservationCounter
	if err := s.db.WithContext(ctx).Where("instance_id = ? AND name IN ?", s.instanceID, names).Find(&rows).Error; err != nil {
		return result, ErrObservationRead
	}
	for _, row := range rows {
		if row.Value < 0 {
			return result, ErrObservationRead
		}
		switch row.Name {
		case syncCount:
			result.SyncCount = row.Value
		case syncNanoseconds:
			result.SyncNanoseconds = row.Value
		default:
			result.Counters[row.Name] = row.Value
		}
	}
	if err := s.db.WithContext(ctx).Model(&models.ActiveSession{}).Where("instance_id = ?", s.instanceID).Count(&result.ActiveSessions).Error; err != nil {
		return result, ErrObservationRead
	}
	return result, nil
}
