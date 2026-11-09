package observability

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func testDatabase(t *testing.T, path string) *gorm.DB {
	t.Helper()
	if path == "" {
		path = ":memory:"
	}
	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	connection.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = connection.Close() })
	if err := database.Exec("PRAGMA busy_timeout=1000").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&models.ObservationCounter{}, &models.ActiveSession{}); err != nil {
		t.Fatal(err)
	}
	return database
}

func testStore(t *testing.T, database *gorm.DB, instanceID string) *Store {
	t.Helper()
	store, err := NewStore(database, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestDurableCountersAndActiveSessionsAreScopedToInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.db")
	database := testDatabase(t, path)
	first := testStore(t, database, "first-instance")
	second := testStore(t, database, "second-instance")
	if err := first.Record(context.Background(), SessionsTotal, 3); err != nil {
		t.Fatal(err)
	}
	if err := second.Record(context.Background(), SessionsTotal, 7); err != nil {
		t.Fatal(err)
	}
	for _, instance := range []string{"first-instance", "first-instance", "second-instance"} {
		if err := database.Create(&models.ActiveSession{InstanceID: instance, Username: "sensitive-user", PID: 123, Kind: "ssh"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	reopened := testStore(t, testDatabase(t, path), "first-instance")
	snapshot, err := reopened.Snapshot(context.Background())
	if err != nil || snapshot.Counters[SessionsTotal] != 3 || snapshot.ActiveSessions != 2 {
		t.Fatalf("incorrect persisted instance snapshot: %+v, %v", snapshot, err)
	}
	if len(snapshot.Counters) != 8 || snapshot.Counters[MFAFailuresTotal] != 0 {
		t.Fatal("initial fixed counters are missing")
	}
	if err := first.ObserveSyncDuration(context.Background(), 125*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := first.ObserveSyncDuration(context.Background(), 375*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	snapshot, err = first.Snapshot(context.Background())
	if err != nil || snapshot.SyncCount != 2 || snapshot.SyncNanoseconds != int64(500*time.Millisecond) {
		t.Fatalf("duration observations were not persisted: %+v, %v", snapshot, err)
	}
}

func TestAtomicCountersAcrossIndependentDatabaseConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	firstDB := testDatabase(t, path)
	secondDB := testDatabase(t, path)
	stores := []*Store{testStore(t, firstDB, "concurrent"), testStore(t, secondDB, "concurrent")}
	errors := make(chan error, 8)
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			for count := 0; count < 20; count++ {
				if err := stores[index%2].Record(context.Background(), AuthFailuresTotal, 1); err != nil {
					errors <- err
					return
				}
			}
		}(worker)
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	snapshot, err := stores[0].Snapshot(context.Background())
	if err != nil || snapshot.Counters[AuthFailuresTotal] != 160 {
		t.Fatalf("concurrent increments were lost: %+v, %v", snapshot, err)
	}
}

func TestObservationAllowlistOverflowAndFailure(t *testing.T) {
	database := testDatabase(t, "")
	store := testStore(t, database, "instance")
	for _, name := range []string{"", "user_secret", "gobastion_sessions_active", syncCount} {
		if err := store.Record(context.Background(), name, 1); err != ErrInvalidObservation {
			t.Fatalf("unknown/noncounter metric accepted: %q", name)
		}
	}
	for _, delta := range []int64{0, -1} {
		if err := store.Record(context.Background(), SessionsTotal, delta); err != ErrInvalidObservation {
			t.Fatal("nonpositive delta accepted")
		}
	}
	if err := store.ObserveSyncDuration(context.Background(), -time.Second); err != ErrInvalidObservation {
		t.Fatal("negative duration accepted")
	}
	if err := store.Record(context.Background(), SessionsTotal, math.MaxInt64); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(context.Background(), SessionsTotal, 1); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil || snapshot.Counters[SessionsTotal] != math.MaxInt64 {
		t.Fatal("counter overflow wrapped or changed SQL type")
	}
	if err := database.Migrator().DropTable(&models.ObservationCounter{}); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(context.Background(), SessionsTotal, 1); err != ErrObservationWrite {
		t.Fatal("missing table did not report observation failure")
	}
	if _, err := store.Snapshot(context.Background()); err != ErrObservationRead {
		t.Fatal("failed collection returned fake zero counters")
	}
}

func TestDurationWriteFailureRollsBackCountAndSum(t *testing.T) {
	database := testDatabase(t, "")
	store := testStore(t, database, "instance")
	query := fmt.Sprintf("CREATE TRIGGER fail_duration_sum BEFORE INSERT ON observation_counters WHEN NEW.name = '%s' BEGIN SELECT RAISE(ABORT, 'injected duration failure'); END", syncNanoseconds)
	if err := database.Exec(query).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.ObserveSyncDuration(context.Background(), time.Second); err != ErrObservationWrite {
		t.Fatal("partial duration observation accepted")
	}
	var count int64
	if err := database.Model(&models.ObservationCounter{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("failed duration observation left a partial count")
	}
}
