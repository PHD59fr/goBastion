package recording

import (
	"encoding/json"
	"errors"
	"fmt"
	"goBastion/internal/utils/validation"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// RetireAccount seals the account boundary without recursively changing history.
// The OS identity must stay reserved; the caller drains registered sessions and
// terminates/verifies all remaining processes before invoking this operation.
func RetireAccount(archive, username string) (resultErr error) {
	if os.Geteuid() != 0 {
		return fmt.Errorf("recording retirement requires root")
	}
	uid, err := recordingUsernameUID(username)
	if err != nil {
		return err
	}
	base, err := openArchiveDirectory(archive, ".", uid)
	if err != nil {
		return err
	}
	defer func() { _ = base.Close() }()
	isolated, err := archiveIsolation(base)
	if err != nil {
		return err
	}
	if !isolated {
		return fmt.Errorf("recording retirement requires isolated storage")
	}
	if err = checkDBPending(base, username); err != nil {
		return err
	}
	if err = checkTemporaryAndPublicationPending(base, username, uid); err != nil {
		return err
	}

	fd, err := unix.Openat(int(base.Fd()), username, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	gid, err := recordingGroupID(AuditorGroup)
	if err != nil {
		return err
	}
	if (st.Uid != uint32(uid) && st.Uid != 0) || st.Gid != uint32(gid) || st.Mode&07777 != 02750 {
		return fmt.Errorf("unsafe recording retirement boundary")
	}
	if err = ValidateNoACL(fd); err != nil {
		return err
	}
	if err = checkAccountPending(fd); err != nil {
		return err
	}

	changed := st.Uid != 0
	committed := false
	defer func() {
		// The caller can restore DB policy on failure; keep the old owner when
		// retirement did not commit. Any storage failure is still fail closed.
		if changed && !committed {
			resultErr = errors.Join(resultErr, unix.Fchown(fd, int(st.Uid), gid), unix.Fchmod(fd, 02750), unix.Fsync(fd))
		}
	}()
	if changed {
		if err = unix.Fchown(fd, 0, gid); err != nil {
			return err
		}
	}

	if err = unix.Fchmod(fd, 02750); err != nil {
		return err
	}
	if err = unix.Fsync(fd); err != nil {
		return err
	}
	if err = base.Sync(); err != nil {
		return err
	}
	committed = true
	return nil
}

func checkDBPending(base *os.File, username string) error {
	fd, err := unix.Openat(int(base.Fd()), ".db-pending", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "pending-recordings")
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Mode&07777 != 0700 {
		return fmt.Errorf("unsafe pending recording inventory")
	}
	entries, err := file.ReadDir(100001)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) > 100000 {
		return fmt.Errorf("too many pending recordings")
	}
	root, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "db-record-") {
			return fmt.Errorf("unknown pending recording entry")
		}
		f, e := root.OpenFile(filepath.Join(entry.Name(), "manifest.json"), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			return fmt.Errorf("unclassified pending recording prevents retirement")
		}
		info, e := f.Stat()
		if e != nil {
			_ = f.Close()
			return e
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm() != 0600 || stat.Nlink != 1 || info.Size() > 8192 {
			_ = f.Close()
			return fmt.Errorf("unsafe pending recording manifest")
		}
		raw, e := io.ReadAll(io.LimitReader(f, 8193))
		_ = f.Close()
		if e != nil {
			return e
		}
		var manifest Manifest
		if e = json.Unmarshal(raw, &manifest); e != nil || !filepath.IsLocal(manifest.Destination) {
			return fmt.Errorf("invalid pending recording manifest")
		}
		if strings.Split(filepath.ToSlash(manifest.Destination), "/")[0] == username {
			return fmt.Errorf("pending database recording prevents account retirement")
		}
	}
	return nil
}

func checkTemporaryAndPublicationPending(base *os.File, username string, uid int) error {
	temp, err := os.Open(os.TempDir())
	if err != nil {
		return err
	}
	temporaryEntries, err := temp.ReadDir(100001)
	_ = temp.Close()
	if err != nil && err != io.EOF {
		return err
	}
	if len(temporaryEntries) > 100000 {
		return fmt.Errorf("temporary recording inventory limit reached")
	}
	var paths []string
	for _, entry := range temporaryEntries {
		if strings.HasPrefix(entry.Name(), "gobastion-db-record-") {
			paths = append(paths, filepath.Join(os.TempDir(), entry.Name()))
		}
	}

	for _, path := range paths {
		fd, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == unix.ENOENT || e == unix.ENOTDIR || e == unix.ELOOP {
			continue
		}
		if e != nil {
			return e
		}
		var st unix.Stat_t
		e = unix.Fstat(fd, &st)
		if e != nil {
			_ = unix.Close(fd)
			return e
		}
		if st.Uid != 0 || st.Mode&07777 != 0700 {
			_ = unix.Close(fd)
			continue
		}
		root, e := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", fd))
		_ = unix.Close(fd)
		if e != nil {
			return e
		}
		manifest, e := pendingManifest(root, "manifest.json")
		_ = root.Close()
		if e != nil {
			return e
		}
		if strings.Split(filepath.ToSlash(manifest.Destination), "/")[0] == username {
			return fmt.Errorf("temporary database recording prevents retirement")
		}
	}
	if base == nil {
		return nil
	}
	dup, err := unix.FcntlInt(base.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dup), "archive-pending-inventory")
	entries, err := dir.ReadDir(100001)
	_ = dir.Close()
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) > 100000 {
		return fmt.Errorf("archive inventory limit reached")
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".publish-") {
			continue
		}
		stageFD, e := unix.Openat(int(base.Fd()), entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == unix.ENOENT {
			continue
		}
		if e != nil {
			return e
		}
		fileFD, e := unix.Openat(stageFD, "recording.gz", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		_ = unix.Close(stageFD)
		if e != nil {
			return fmt.Errorf("unclassified publication prevents retirement")
		}
		var st unix.Stat_t
		e = unix.Fstat(fileFD, &st)
		_ = unix.Close(fileFD)
		if e != nil {
			return e
		}
		if st.Uid == 0 || st.Uid == uint32(uid) {
			return fmt.Errorf("pending publication prevents retirement")
		}
	}
	return nil
}
func pendingManifest(root *os.Root, path string) (Manifest, error) {
	var manifest Manifest
	f, err := root.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return manifest, fmt.Errorf("unclassified pending recording prevents retirement")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return manifest, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || info.Mode().Perm() != 0600 || st.Nlink != 1 || info.Size() > 8192 {
		return manifest, fmt.Errorf("unsafe pending recording manifest")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return manifest, err
	}
	if err = json.Unmarshal(raw, &manifest); err != nil || !filepath.IsLocal(manifest.Destination) {
		return manifest, fmt.Errorf("invalid pending recording manifest")
	}
	return manifest, nil
}

func checkAccountPending(fd int) error {
	count := 0
	var walk func(int, int) error
	walk = func(parent, depth int) error {
		if depth > 16 {
			return fmt.Errorf("recording retirement depth limit reached")
		}
		dup, err := unix.FcntlInt(uintptr(parent), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return err
		}
		dir := os.NewFile(uintptr(dup), "retirement-inventory")
		defer func() { _ = dir.Close() }()
		for {
			entries, readErr := dir.ReadDir(128)
			if readErr != nil && readErr != io.EOF {
				return readErr
			}
			for _, entry := range entries {
				count++
				if count > 100000 {
					return fmt.Errorf("recording retirement entry limit reached")
				}
				var childStat unix.Stat_t
				if err := unix.Fstatat(parent, entry.Name(), &childStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				if childStat.Mode&unix.S_IFMT == unix.S_IFLNK {
					return fmt.Errorf("symlink in retirement namespace")
				}
				if childStat.Mode&unix.S_IFMT != unix.S_IFDIR {
					continue
				}
				child, err := unix.Openat(parent, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					return err
				}
				if strings.HasPrefix(entry.Name(), ".ssh-record-") || strings.HasPrefix(entry.Name(), ".publish-") {
					f := os.NewFile(uintptr(child), "retirement-spool")
					items, e := f.ReadDir(1)
					_ = f.Close()
					if e != nil && e != io.EOF {
						return e
					}
					if len(items) != 0 {
						return fmt.Errorf("pending recording prevents retirement")
					}
				} else {
					e := walk(child, depth+1)
					_ = unix.Close(child)
					if e != nil {
						return e
					}
				}
			}
			if readErr == io.EOF {
				return nil
			}
		}
	}
	return walk(fd, 0)
}

// IsRetiredAccount also supports a protected archive whose historical OS
// account is gone. Pending captures remain an explicit offline-recovery gate.
func IsRetiredAccount(archive, username string) (bool, error) {
	if username != strings.ToLower(username) || !validation.IsValidManagedUsername(username) {
		return false, fmt.Errorf("invalid retired account name")
	}
	base, err := openArchiveDirectory(archive, ".", 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, checkTemporaryAndPublicationPending(nil, username, 0)
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = base.Close() }()
	isolated, err := archiveIsolation(base)
	if err != nil {
		return false, err
	}
	if !isolated {
		return false, fmt.Errorf("retirement requires isolated storage")
	}
	if err = checkDBPending(base, username); err != nil {
		return false, err
	}
	if err = checkTemporaryAndPublicationPending(base, username, 0); err != nil {
		return false, err
	}
	fd, err := unix.Openat(int(base.Fd()), username, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return false, err
	}
	gid, err := recordingGroupID(AuditorGroup)
	if err != nil {
		return false, err
	}
	if st.Uid != 0 || st.Gid != uint32(gid) || st.Mode&07777 != 02750 {
		return false, nil
	}
	if err = ValidateNoACL(fd); err != nil {
		return false, err
	}
	if err = checkAccountPending(fd); err != nil {
		return false, err
	}
	return true, nil
}
