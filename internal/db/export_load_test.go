package db

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"goBastion/internal/models"
)

// This opt-in measurement isolates the effect of a retained export snapshot on
// a bounded SQLite workload. It deliberately holds the snapshot while the same
// write workload used for the baseline runs. The measurements describe this
// local fixture, including process-wide Go memory use; they are not deployment
// capacity limits or performance gates. The direct AES key excludes KDF cost.
func TestSQLiteExportBoundedLoadMeasurement(t *testing.T) {
	if os.Getenv("GOB_EXPORT_LOAD_MEASUREMENT") != "1" {
		t.Skip("set GOB_EXPORT_LOAD_MEASUREMENT=1 for the bounded export-load measurement")
	}
	t.Setenv("DB_EXPORT_KEY", lifecycleExportKey)
	source, writer, pool, path := openSQLiteExportLifecycle(t)
	const fixtureRows = 256
	fixtures := make([]models.BastionInstance, fixtureRows)
	for i := range fixtures {
		fixtures[i] = models.BastionInstance{
			InstanceID: fmt.Sprintf("export-load-%04d", i),
			Config:     strings.Repeat("s", 8*1024),
		}
	}
	if err := source.CreateInBatches(&fixtures, 32).Error; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	baseline := measureExportLoadWrites(t, ctx, writer, fixtures, "baseline")
	if busy, _, _ := sqliteCheckpoint(t, writer); busy != 0 {
		t.Fatal("baseline checkpoint was busy")
	}

	ready, release := pauseExportSnapshot(t, source)
	defer release()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	sampled := make(chan runtime.MemStats, 1)
	stopSampling := make(chan struct{})
	go func() {
		peak := before
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			var current runtime.MemStats
			runtime.ReadMemStats(&current)
			if current.HeapAlloc > peak.HeapAlloc {
				peak = current
			}
			select {
			case <-stopSampling:
				sampled <- peak
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() {
		if stopSampling != nil {
			close(stopSampling)
			<-sampled
		}
	}()

	output := &countingExportLoadWriter{}
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- Export(source.WithContext(ctx), output, nil) }()
	awaitExportLifecycle(t, ready)
	if stats := pool.Stats(); stats.InUse != 1 {
		t.Fatalf("held export used %d connections, want one", stats.InUse)
	}
	held := measureExportLoadWrites(t, ctx, writer, fixtures, "held-snapshot")
	busy, frames, checkpointed := sqliteCheckpoint(t, writer)
	if busy != 1 || frames <= checkpointed {
		t.Fatalf("held snapshot did not retain WAL: busy=%d frames=%d checkpointed=%d", busy, frames, checkpointed)
	}
	wal, err := os.Stat(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	retained := time.Since(started)
	release()
	if err := finishExportLifecycle(t, done); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	close(stopSampling)
	peak := <-sampled
	stopSampling = nil
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	assertExportPoolReleased(t, pool)
	if busy, frames, checkpointed := sqliteCheckpoint(t, writer); busy != 0 || frames != 0 || checkpointed != 0 {
		t.Fatalf("completed export retained WAL: busy=%d frames=%d checkpointed=%d", busy, frames, checkpointed)
	}
	if output.bytes == 0 {
		t.Fatal("export wrote no encrypted output")
	}
	t.Logf("fixture: rows=%d initial_config_bytes=%d writes_per_phase=%d update_bytes=%d; direct AES key; encrypted output discarded", fixtureRows, 8*1024, len(baseline), 32*1024)
	t.Logf("writer latency: baseline p50=%s p95=%s max=%s; held snapshot p50=%s p95=%s max=%s", baseline[len(baseline)/2], baseline[len(baseline)*95/100], baseline[len(baseline)-1], held[len(held)/2], held[len(held)*95/100], held[len(held)-1])
	t.Logf("snapshot held=%s export elapsed=%s encrypted_output_bytes=%d WAL_bytes=%d frames=%d checkpointed=%d; WAL truncated and pool returned after export", retained, elapsed, output.bytes, wal.Size(), frames, checkpointed)
	t.Logf("process-wide Go memory during export plus concurrent writes: allocated_bytes=%d sampled_peak_heap_bytes=%d heap_before_bytes=%d heap_after_bytes=%d; 5ms sampling may miss peaks", after.TotalAlloc-before.TotalAlloc, peak.HeapAlloc, before.HeapAlloc, after.HeapAlloc)
}

func measureExportLoadWrites(t *testing.T, ctx context.Context, writer *gorm.DB, fixtures []models.BastionInstance, phase string) []time.Duration {
	t.Helper()
	const writes = 128
	latencies := make([]time.Duration, 0, writes)
	// A paced, fixed-size workload bounds disk use while retaining the snapshot
	// for at least half a second. Latencies exclude the pacing delay.
	ticker := time.NewTicker(4 * time.Millisecond)
	defer ticker.Stop()
	for i := range writes {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
		prefix := fmt.Sprintf("%s:%d:", phase, i)
		value := prefix + strings.Repeat("w", 32*1024-len(prefix))
		started := time.Now()
		result := writer.WithContext(ctx).Model(&fixtures[i%64]).Update("config", value)
		latencies = append(latencies, time.Since(started))
		if result.Error != nil || result.RowsAffected != 1 {
			t.Fatalf("%s write %d: rows=%d error=%v", phase, i, result.RowsAffected, result.Error)
		}
	}
	slices.Sort(latencies)
	return latencies
}

type countingExportLoadWriter struct{ bytes int }

func (w *countingExportLoadWriter) Write(data []byte) (int, error) {
	w.bytes += len(data)
	return len(data), nil
}

var _ io.Writer = (*countingExportLoadWriter)(nil)
