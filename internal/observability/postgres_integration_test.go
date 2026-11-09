package observability

import (
	"context"
	"math"
	"os"
	"sync"
	"testing"
	"time"

	"goBastion/internal/models"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Use a dedicated disposable database: this test creates the observation and
// registry schemas but deletes only rows bearing its own random instance ID.
func TestPostgresConcurrentObservations(t *testing.T) {
	dsn := os.Getenv("GOB_OBSERVABILITY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL observation test database not configured")
	}
	open := func() *gorm.DB {
		database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatal("cannot open dedicated observation test database")
		}
		connection, err := database.DB()
		if err != nil {
			t.Fatal("cannot access observation test pool")
		}
		connection.SetMaxOpenConns(4)
		t.Cleanup(func() { _ = connection.Close() })
		return database
	}
	first, second := open(), open()
	if err := first.AutoMigrate(&models.ObservationCounter{}, &models.ActiveSession{}); err != nil {
		t.Fatal("cannot prepare observation test schema")
	}
	instance := "observation-test-" + uuid.NewString()
	t.Cleanup(func() {
		if err := first.Where("instance_id = ?", instance).Delete(&models.ObservationCounter{}).Error; err != nil {
			t.Error("cannot clean observation test rows")
		}
	})
	stores := []*Store{testStore(t, first, instance), testStore(t, second, instance)}
	const workers, iterations = 8, 20
	var group sync.WaitGroup
	failures := make(chan error, workers)
	for worker := range workers {
		group.Go(func() {
			store := stores[worker%len(stores)]
			for range iterations {
				if err := store.Record(context.Background(), AccessDeniedTotal, 1); err != nil {
					failures <- err
					return
				}
				if err := store.ObserveSyncDuration(context.Background(), time.Millisecond); err != nil {
					failures <- err
					return
				}
			}
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	snapshot, err := stores[1].Snapshot(context.Background())
	if err != nil || snapshot.Counters[AccessDeniedTotal] != workers*iterations || snapshot.SyncCount != workers*iterations || snapshot.SyncNanoseconds != workers*iterations*int64(time.Millisecond) {
		t.Fatalf("concurrent observation loss: %+v, %v", snapshot, err)
	}
	if err := stores[0].Record(context.Background(), SessionsTotal, math.MaxInt64); err != nil {
		t.Fatal(err)
	}
	if err := stores[1].Record(context.Background(), SessionsTotal, 1); err != nil {
		t.Fatal(err)
	}
	snapshot, err = stores[0].Snapshot(context.Background())
	if err != nil || snapshot.Counters[SessionsTotal] != math.MaxInt64 {
		t.Fatal("PostgreSQL counter did not saturate safely")
	}
	other, err := testStore(t, second, instance+"-other").Snapshot(context.Background())
	if err != nil || other.Counters[AccessDeniedTotal] != 0 || other.SyncCount != 0 {
		t.Fatal("observation data crossed instance scope")
	}
}
