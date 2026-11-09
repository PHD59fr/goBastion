package observability

import (
	"context"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PendingStats struct {
	Bytes          int64
	OldestModified time.Time
}

// ScanPending measures only the configured persistent archive tree. It counts
// raw/compressed files inside recognized SSH/DB pending directories, excluding
// manifests, locks, publication stages and finalized recordings elsewhere.
// Temporary fallback spools outside this root are deliberately out of scope.
func ScanPending(ctx context.Context, path string) (PendingStats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result := PendingStats{}
	unavailable := errors.New("pending recording measurements unavailable")
	if path == "" {
		return result, unavailable
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return result, unavailable
	}
	defer func() { _ = root.Close() }()
	visited := 0
	err = fs.WalkDir(root.FS(), ".", func(relative string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		visited++
		if visited > 100000 {
			return unavailable
		}
		if walkErr != nil {
			// A finalizer may remove a spool while a scrape is walking it.
			if os.IsNotExist(walkErr) {
				return nil
			}
			return unavailable
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".publish-") {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		isSSH := len(parts) == 4 && strings.HasPrefix(parts[2], ".ssh-record-")
		isDB := len(parts) == 3 && parts[0] == ".db-pending" && strings.HasPrefix(parts[1], "db-record-")
		if !isSSH && !isDB {
			return nil
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".ttyrec") && !strings.HasSuffix(name, ".gz") && !strings.HasSuffix(name, ".gz.tmp") {
			return nil
		}
		info, err := root.Lstat(relative)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > math.MaxInt64-result.Bytes {
			return unavailable
		}
		result.Bytes += info.Size()
		modified := info.ModTime()
		if result.OldestModified.IsZero() || modified.Before(result.OldestModified) {
			result.OldestModified = modified
		}
		return nil
	})
	if err != nil {
		return PendingStats{}, unavailable
	}
	return result, nil
}
