package recording

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// Recover is called by the privileged startup/sync process. Each spool has its
// own nonblocking lock, shared with the recorder and any concurrent recoverer.
func Recover(archive string, log *slog.Logger) {
	root, err := os.OpenRoot(archive)
	if err == nil {
		defer func() { _ = root.Close() }()
		_ = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				log.Warn("recording_recovery_scan_failed", "path", path, "error", walkErr)
				return fs.SkipDir
			}
			if !d.IsDir() {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".publish-") {
				if staging, err := root.OpenRoot(path); err == nil {
					cleanStaging(staging, path, root)
					_ = staging.Close()
				}
				return fs.SkipDir
			}
			parts := strings.Split(filepath.ToSlash(path), "/")
			isSSH := len(parts) == 3 && strings.HasPrefix(d.Name(), ".ssh-record-")
			isDB := len(parts) == 2 && parts[0] == ".db-pending" && strings.HasPrefix(d.Name(), "db-record-")
			if !isSSH && !isDB {
				return nil
			}
			spool, err := root.OpenRoot(path)
			if err != nil {
				return fs.SkipDir
			}
			recoverOne(archive, spool, path, isSSH, log)
			_ = spool.Close()
			return fs.SkipDir
		})
	}
	// Older temporary DB spools are recoverable if they carry a manifest. Spools
	// created before manifests were introduced remain available for manual recovery.
	entries, _ := filepath.Glob(filepath.Join(os.TempDir(), "gobastion-db-record-*"))
	for _, path := range entries {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			continue
		}
		spool, err := os.OpenRoot(path)
		if err != nil {
			continue
		}
		recoverOne(archive, spool, path, false, log)
		_ = spool.Close()
	}
}

func recoverOne(archive string, spool *os.Root, path string, isSSH bool, log *slog.Logger) {
	info, err := spool.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	owner := int(stat.Uid)
	if isSSH {
		parts := strings.Split(filepath.ToSlash(path), "/")
		account, err := user.Lookup(parts[0])
		if err != nil || account.Uid != strconv.Itoa(owner) {
			return
		}
	} else if owner != 0 && owner != os.Geteuid() {
		return
	}
	lock, err := spool.OpenFile(".lock", os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	defer func() { _ = lock.Close() }()
	if info, err := lock.Stat(); err != nil || regular(info) != nil {
		return
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return
	}
	manifest, err := spool.OpenFile("manifest.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	data, err := io.ReadAll(io.LimitReader(manifest, 8193))
	_ = manifest.Close()
	if err != nil || len(data) > 8192 {
		return
	}
	var m Manifest
	if json.Unmarshal(data, &m) != nil || !filepath.IsLocal(m.Destination) || filepath.Base(m.Raw) != m.Raw || !strings.HasSuffix(m.Raw, ".ttyrec") {
		return
	}
	if isSSH && m.Destination != filepath.Join(filepath.Dir(path), m.Raw+".gz") {
		return
	}
	raw, err := spool.OpenFile(m.Raw, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	defer func() { _ = raw.Close() }()
	rawInfo, err := raw.Stat()
	if err != nil || regular(rawInfo) != nil || rawInfo.Size() == 0 {
		return
	}
	if rawStat, ok := rawInfo.Sys().(*syscall.Stat_t); !ok || int(rawStat.Uid) != owner {
		return
	}
	if err := recompress(archive, spool, raw, m, owner); err != nil {
		log.Error("recording_recovery_failed", "spool", path, "error", err)
		return
	}
	// Remove only entries inside the locked directory. Never follow symlinks or
	// recursively remove a directory selected through untrusted manifest content.
	entries, err := fs.ReadDir(spool.FS(), ".")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		_ = spool.Remove(entry.Name())
	}
	log.Info("recording_recovered", "spool", path, "destination", m.Destination)
	// Leave the now-empty directory until after closing its lock. Removing it is
	// best effort; scanning an empty directory is harmless after a crash.
	if filepath.IsAbs(path) {
		_ = os.Remove(path)
	} else {
		root, err := os.OpenRoot(archive)
		if err == nil {
			_ = root.Remove(path)
			_ = root.Close()
		}
	}
}

func recompress(archive string, spool *os.Root, raw *os.File, m Manifest, owner int) error {
	// An archive may already have been committed when the previous process died.
	if sameRecording(archive, m.Destination, raw) {
		return nil
	}
	if _, err := raw.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// The caller holds the spool lock: no active writer owns these retry files.
	entries, err := fs.ReadDir(spool.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), ".recovery-") && strings.HasSuffix(entry.Name(), ".gz.tmp") {
			if err := spool.Remove(entry.Name()); err != nil {
				return err
			}
		}
	}
	name := ".recovery-" + uuid.NewString() + ".gz.tmp"
	defer func() { _ = spool.Remove(name) }()
	out, err := spool.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	if info, err := out.Stat(); err != nil || regular(info) != nil {
		_ = out.Close()
		return fmt.Errorf("invalid recovery output")
	}
	gz := gzip.NewWriter(out)
	_, copyErr := io.Copy(gz, raw)
	closeErr := gz.Close()
	syncErr := out.Sync()
	fileErr := out.Close()
	if err := errors.Join(copyErr, closeErr, syncErr, fileErr); err != nil {
		return err
	}
	// Keep an open directory descriptor as the source anchor during publication.
	anchor, err := spool.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = anchor.Close() }()
	source := fmt.Sprintf("/proc/%d/fd/%d/%s", os.Getpid(), anchor.Fd(), name)
	return Publish(archive, source, m.Destination, owner)
}

func sameRecording(archive, relative string, raw *os.File) bool {
	root, err := os.OpenRoot(archive)
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(relative, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || regular(info) != nil {
		return false
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false
	}
	defer func() { _ = gz.Close() }()
	info, err := raw.Stat()
	if err != nil {
		return false
	}
	if _, err := raw.Seek(0, io.SeekStart); err != nil {
		return false
	}
	expected, actual := sha256.New(), sha256.New()
	n, err := io.Copy(actual, io.LimitReader(gz, info.Size()+1))
	if err != nil || n != info.Size() {
		return false
	}
	if _, err := io.Copy(expected, raw); err != nil {
		return false
	}
	if string(expected.Sum(nil)) != string(actual.Sum(nil)) {
		return false
	}
	parent, err := root.Open(filepath.Dir(relative))
	if err != nil {
		return false
	}
	err = parent.Sync()
	_ = parent.Close()
	return err == nil
}

func cleanStaging(staging *os.Root, path string, archive *os.Root) {
	info, err := staging.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	if int(stat.Uid) != 0 {
		parts := strings.Split(filepath.ToSlash(path), "/")
		account, err := user.Lookup(parts[0])
		if err != nil || account.Uid != strconv.Itoa(int(stat.Uid)) {
			return
		}
	}
	lock, err := staging.OpenFile(".lock", os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	defer func() { _ = lock.Close() }()
	if info, err := lock.Stat(); err != nil || regular(info) != nil {
		return
	}
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return
	}
	_ = staging.Remove("recording.gz")
	_ = staging.Remove(".lock")
	_ = archive.Remove(path)
}
