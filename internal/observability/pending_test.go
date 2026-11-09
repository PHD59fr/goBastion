package observability

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingScanMeasuresOnlyRecognizedSpoolsAndSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-2 * time.Hour)
	write := func(relative string, bytes int, modified time.Time) {
		t.Helper()
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, make([]byte, bytes), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	write("alice/server/.ssh-record-one/session.ttyrec", 5, old)
	write(".db-pending/db-record-two/session.ttyrec.gz", 7, time.Now())
	write("alice/server/finalized.ttyrec.gz", 99, old.Add(-time.Hour))
	write("alice/server/.ssh-record-one/manifest.json", 999, old)
	write("alice/server/.ssh-record-one/.lock", 999, old)
	write(".publish-one/alice/server/.ssh-record-fake/fake.ttyrec", 999, old)
	outside := filepath.Join(t.TempDir(), "outside.ttyrec")
	if err := os.WriteFile(outside, make([]byte, 999), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "alice/server/.ssh-record-one/link.ttyrec")); err != nil {
		t.Fatal(err)
	}
	stats, err := ScanPending(context.Background(), root)
	if err != nil || stats.Bytes != 12 || !stats.OldestModified.Equal(old) {
		t.Fatalf("incorrect pending spool measurements: %+v, %v", stats, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ScanPending(ctx, root); err == nil {
		t.Fatal("cancelled scan reported successful zero gauges")
	}
	if _, err := ScanPending(context.Background(), filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing spool reported successful zero gauges")
	}
	empty, err := ScanPending(context.Background(), t.TempDir())
	if err != nil || empty.Bytes != 0 || !empty.OldestModified.IsZero() {
		t.Fatal("actual empty spool was not reported as zero")
	}
}
