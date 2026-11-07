package recording

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestRegressionFailedRetriesHaveBoundedStorage(t *testing.T) {
	archive, spool, destination, lock := recoveryFixture(t)
	_ = lock.Close()
	if err := os.WriteFile(filepath.Join(archive, destination), []byte("conflict"), 0600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for range 3 {
		Recover(archive, logger)
	}
	files, err := filepath.Glob(filepath.Join(spool, ".recovery-*.gz.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) > 1 {
		t.Fatalf("three failed retries left %d full compressed copies beside the raw recording", len(files))
	}
}
