package permissions

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"goBastion/internal/recording"
	"golang.org/x/sys/unix"
)

// checkOfflineUID rejects any local process with a managed UID, including a
// recycled prior owner. It cannot prove that other hosts have stopped.
func checkOfflineUID(target uint32) error {
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	if len(processes) > 100000 {
		return errors.New("local process inventory limit reached")
	}
	for _, process := range processes {
		if _, err := strconv.Atoi(process.Name()); err != nil {
			continue
		}
		f, err := os.Open(filepath.Join("/proc", process.Name(), "status"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
		_ = f.Close()
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || len(data) > 64<<10 {
			return errors.New("cannot inspect bounded local process status")
		}
		uidLines := 0
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "Uid:") {
				continue
			}
			uidLines++
			if uidLines != 1 {
				return errors.New("ambiguous local process identity")
			}
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) != 4 {
				return errors.New("cannot inspect local process identity")
			}
			for _, field := range fields {
				uid, err := strconv.ParseUint(field, 10, 32)
				if err != nil {
					return err
				}
				if uid >= 1000 && uid < 65000 || target != 0 && uint32(uid) == target {
					return errors.New("managed account has an active local process")
				}
			}
		}
		if uidLines != 1 {
			return errors.New("missing local process identity")
		}
	}
	return nil
}

func openBackupParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) || path != filepath.Clean(path) || filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return -1, "", errors.New("invalid backup path")
	}
	parent, err := openAbsoluteDir(filepath.Dir(path), true)
	if err != nil {
		return -1, "", err
	}
	return parent, filepath.Base(path), nil
}

func checkBackupLocation(archive, backup string) error {
	if !filepath.IsAbs(backup) || backup != filepath.Clean(backup) || backup == archive || strings.HasPrefix(backup, archive+string(filepath.Separator)) {
		return errors.New("backup must be an absolute path outside the archive")
	}
	return nil
}

func writeBackup(path string, p PlanData) error {
	parent, name, err := openBackupParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	data, err := Encode(p)
	if err != nil {
		return err
	}
	if len(data)+1 > maxBackupBytes {
		return errors.New("backup metadata size limit reached")
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".recording-permissions-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(parent, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(parent, temporary, 0) }()
	f := os.NewFile(uintptr(fd), "recording-permissions-backup")
	defer func() { _ = f.Close() }()
	if err = unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err = unix.Fchmod(fd, 0600); err != nil {
		return err
	}
	if err = recording.ValidateNoACL(fd); err != nil {
		return err
	}
	if _, err = f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = unix.Renameat2(parent, temporary, parent, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return unix.Fsync(parent)
}

func readBackup(path string) (PlanData, error) {
	parent, name, err := openBackupParent(path)
	if err != nil {
		return PlanData{}, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, s, err := openChild(parent, name, false)
	if err != nil {
		return PlanData{}, err
	}
	f := os.NewFile(uintptr(fd), "recording-permissions-backup")
	defer func() { _ = f.Close() }()
	if s.Uid != 0 || s.Gid != 0 || s.Mode&07777 != 0600 || s.Size < 1 || s.Size > maxBackupBytes {
		return PlanData{}, errors.New("unsafe backup metadata")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBackupBytes+1))
	if err != nil || len(data) > maxBackupBytes {
		return PlanData{}, errors.New("backup read failed")
	}
	var p PlanData
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&p); err != nil {
		return PlanData{}, err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return PlanData{}, errors.New("trailing backup metadata")
	}
	if err = unix.Fsync(fd); err != nil {
		return PlanData{}, err
	}
	if err = unix.Fsync(parent); err != nil {
		return PlanData{}, err
	}
	return p, nil
}

func validateBackup(p PlanData, archive, account string, id *identity) error {
	if p.Version != Version || p.Archive != archive || p.User != account || p.Retired != id.retired || len(p.Entries) < 2 || len(p.Entries) > MaxEntries {
		return errors.New("backup identity or version mismatch")
	}
	seen := make(map[string]bool, len(p.Entries))
	for i, e := range p.Entries {
		if err := noteOldUID(id, e.UID); err != nil {
			return err
		}
		if seen[e.Path] || e.Dev != p.RootDev || e.Ino == 0 {
			return errors.New("invalid backup inode inventory")
		}
		seen[e.Path] = true
		switch i {
		case 0:
			if e.Path != "." || e.Ino != p.RootIno || e.DesiredUID != 0 || e.DesiredGID != id.shared || e.DesiredMode != 0751 {
				return errors.New("invalid backup archive root")
			}
		case 1:
			if e.Path != account || e.DesiredUID != desiredUID(*id) || e.DesiredGID != id.auditors || e.DesiredMode != 02750 {
				return errors.New("invalid backup account")
			}
		default:
			parts := strings.Split(e.Path, "/")
			if len(parts) < 2 || len(parts) > 4 || parts[0] != account || parts[1] == "" || strings.HasPrefix(parts[1], ".") || !filepath.IsLocal(e.Path) {
				return errors.New("invalid backup path")
			}
			if len(parts) == 2 {
				if e.DesiredUID != desiredUID(*id) || e.DesiredGID != id.auditors || e.DesiredMode != 02750 {
					return errors.New("invalid backup directory metadata")
				}
			} else if len(parts) == 4 {
				if id.retired {
					return errors.New("retired backup contains pending private spool content")
				}
				if !strings.HasPrefix(parts[2], ".ssh-record-") && !strings.HasPrefix(parts[2], ".publish-") || parts[3] == "" || e.DesiredUID != e.UID || e.DesiredGID != e.GID || e.DesiredMode != 0600 || e.Mode != 0600 || e.UID != 0 && e.UID != id.uid {
					return errors.New("invalid private spool file metadata")
				}
			} else if strings.HasPrefix(parts[2], ".") {
				if !strings.HasPrefix(parts[2], ".ssh-record-") && !strings.HasPrefix(parts[2], ".publish-") || e.DesiredUID != e.UID || e.DesiredGID != e.GID || e.DesiredMode != e.Mode {
					return errors.New("invalid private spool metadata")
				}
				if e.UID != 0 && e.UID != id.uid || e.Mode != 0700 && e.Mode != 02700 {
					return errors.New("unsafe private spool metadata")
				}
			} else if !isRecordingArtifact(parts[2]) || e.DesiredUID != desiredUID(*id) || e.DesiredGID != id.auditors || e.DesiredMode != 0640 {
				return errors.New("invalid backup recording metadata")
			}
		}
		if e.DesiredUID == e.UID && e.DesiredGID == e.GID && e.DesiredMode == e.Mode && strings.Contains(e.Path, "/.") {
			continue
		}
		if !validOld(e, *id) {
			return errors.New("invalid legacy backup metadata")
		}
	}
	if id.retired && id.uid != 0 {
		if _, assigned := id.managed[id.uid]; assigned {
			return errors.New("prior recording UID is now assigned to another account")
		}
	}
	return nil
}

func acceptable(s unix.Stat_t, e Metadata) bool {
	if uint64(s.Dev) != e.Dev || s.Ino != e.Ino {
		return false
	}
	mode := s.Mode & 07777
	if (s.Uid != e.UID && s.Uid != e.DesiredUID) || (s.Gid != e.GID && s.Gid != e.DesiredGID) {
		return false
	}
	return mode == e.Mode || mode == e.DesiredMode || mode == e.Mode&^uint32(unix.S_ISGID|unix.S_ISUID) || mode == e.DesiredMode&^uint32(unix.S_ISGID|unix.S_ISUID)
}

func unchanged(s unix.Stat_t, e Metadata) bool {
	return uint64(s.Dev) == e.Dev && s.Ino == e.Ino && s.Uid == e.UID && s.Gid == e.GID && s.Mode&07777 == e.Mode
}

func inspect(p PlanData, root int) error {
	indexed := make(map[string]Metadata, len(p.Entries))
	for _, e := range p.Entries {
		indexed[e.Path] = e
	}
	rs, err := stat(root)
	if err != nil || !acceptable(rs, indexed["."]) {
		return errors.New("archive inode or metadata changed")
	}
	accountFD, as, err := openChild(root, p.User, true)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(accountFD) }()
	if !acceptable(as, indexed[p.User]) {
		return errors.New("account inode or metadata changed")
	}
	servers, err := names(accountFD)
	if err != nil {
		return err
	}
	count := 2
	for _, server := range servers {
		path := p.User + "/" + server
		e, ok := indexed[path]
		if !ok {
			return errors.New("account namespace changed")
		}
		fd, s, err := openChild(accountFD, server, true)
		if err != nil {
			return err
		}
		if !acceptable(s, e) {
			_ = unix.Close(fd)
			return errors.New("server inode or metadata changed")
		}
		count++
		files, err := names(fd)
		if err != nil {
			_ = unix.Close(fd)
			return err
		}
		for _, name := range files {
			path := path + "/" + name
			e, ok := indexed[path]
			if !ok {
				_ = unix.Close(fd)
				return errors.New("recording namespace changed")
			}
			isDir := strings.HasPrefix(name, ".")
			child, s, err := openChild(fd, name, isDir)
			if err != nil {
				_ = unix.Close(fd)
				return err
			}
			if isDir && !unchanged(s, e) || !isDir && !acceptable(s, e) {
				_ = unix.Close(child)
				_ = unix.Close(fd)
				return errors.New("recording inode or metadata changed")
			}
			count++
			if isDir {
				spoolEntries, err := names(child)
				if err != nil {
					_ = unix.Close(child)
					_ = unix.Close(fd)
					return err
				}
				for _, spoolName := range spoolEntries {
					spoolPath := path + "/" + spoolName
					spoolMeta, ok := indexed[spoolPath]
					if !ok {
						_ = unix.Close(child)
						_ = unix.Close(fd)
						return errors.New("private spool namespace changed")
					}
					spoolFile, spoolStat, err := openChild(child, spoolName, false)
					if err != nil {
						_ = unix.Close(child)
						_ = unix.Close(fd)
						return err
					}
					_ = unix.Close(spoolFile)
					if !unchanged(spoolStat, spoolMeta) {
						_ = unix.Close(child)
						_ = unix.Close(fd)
						return errors.New("private spool inode changed")
					}
					count++
				}
			}
			_ = unix.Close(child)
		}
		_ = unix.Close(fd)
	}
	if count != len(p.Entries) {
		return errors.New("recording inventory changed")
	}
	return nil
}

func openEntry(root int, path string, expected map[string]Metadata) (int, int, string, unix.Stat_t, error) {
	if path == "." {
		s, err := stat(root)
		return root, -1, "", s, err
	}
	parts := strings.Split(path, "/")
	parent := root
	for i := 0; i < len(parts)-1; i++ {
		fd, st, err := openChild(parent, parts[i], true)
		if parent != root {
			_ = unix.Close(parent)
		}
		if err != nil {
			return -1, -1, "", unix.Stat_t{}, err
		}
		prefix := strings.Join(parts[:i+1], "/")
		if e, ok := expected[prefix]; !ok || !acceptable(st, e) {
			_ = unix.Close(fd)
			return -1, -1, "", unix.Stat_t{}, errors.New("recording ancestor changed")
		}
		parent = fd
	}
	name := parts[len(parts)-1]
	directory := len(parts) < 3 || strings.HasPrefix(name, ".")
	fd, s, err := openChild(parent, name, directory)
	if err != nil {
		if parent != root {
			_ = unix.Close(parent)
		}
		return -1, -1, "", s, err
	}
	return fd, parent, name, s, nil
}

func change(root int, e Metadata, rollback bool, expected map[string]Metadata) error {
	if strings.Contains(e.Path, "/.") {
		return nil
	}
	fd, parent, name, s, err := openEntry(root, e.Path, expected)
	if err != nil {
		return err
	}
	if fd != root {
		defer func() { _ = unix.Close(fd) }()
	}
	if parent >= 0 && parent != root {
		defer func() { _ = unix.Close(parent) }()
	}
	if !acceptable(s, e) {
		return fmt.Errorf("recording inode changed: %s", e.Path)
	}
	var named unix.Stat_t
	if parent >= 0 {
		if err = unix.Fstatat(parent, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || named.Dev != s.Dev || named.Ino != s.Ino {
			return errors.New("recording namespace changed before write")
		}
	}
	current, err := stat(fd)
	if err != nil || !acceptable(current, e) || current.Mode&unix.S_IFMT == unix.S_IFREG && current.Nlink != 1 {
		return errors.New("recording inode changed before write")
	}
	if err = recording.ValidateNoACL(fd); err != nil {
		return err
	}
	uid, gid, mode := e.DesiredUID, e.DesiredGID, e.DesiredMode
	if rollback {
		uid, gid, mode = e.UID, e.GID, e.Mode
	}
	if s.Uid != uid || s.Gid != gid {
		if err = unix.Fchown(fd, int(uid), int(gid)); err != nil {
			return err
		}
	}
	if err = unix.Fchmod(fd, mode); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func lockArchive(archive string) (int, unix.Stat_t, error) {
	fd, err := openAbsoluteDir(archive, false)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	st, err := stat(fd)
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("unsafe archive lock inode")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, errors.New("recording archive migration is already running")
	}
	return fd, st, nil
}

func unlockArchive(fd int) {
	_ = unix.Flock(fd, unix.LOCK_UN)
	_ = unix.Close(fd)
}

// Apply creates a durable exclusive backup before mutation. An existing backup
// is a resume request; it is never overwritten.
func Apply(archive, account, backup string, retired ...bool) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("root required")
	}
	if err := checkBackupLocation(archive, backup); err != nil {
		return err
	}
	lock, rootIdentity, err := lockArchive(archive)
	if err != nil {
		return err
	}
	defer unlockArchive(lock)
	isRetired := len(retired) > 0 && retired[0]
	id, err := identities(account, isRetired)
	if err != nil {
		return err
	}
	p, err := readBackup(backup)
	newBackup := false
	if os.IsNotExist(err) {
		p, err = Plan(archive, account, isRetired)
		if err != nil {
			return err
		}
		newBackup = true
	} else if err != nil {
		return err
	}
	if err = validateBackup(p, archive, account, &id); err != nil {
		return err
	}
	if err = checkOfflineUID(id.uid); err != nil {
		return err
	}
	if newBackup {
		if err = writeBackup(backup, p); err != nil {
			return err
		}
	}
	return execute(p, false, rootIdentity)
}

func Rollback(archive, account, backup string, retired ...bool) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("root required")
	}
	if err := checkBackupLocation(archive, backup); err != nil {
		return err
	}
	lock, rootIdentity, err := lockArchive(archive)
	if err != nil {
		return err
	}
	defer unlockArchive(lock)
	isRetired := len(retired) > 0 && retired[0]
	id, err := identities(account, isRetired)
	if err != nil {
		return err
	}
	p, err := readBackup(backup)
	if err != nil {
		return err
	}
	if err = validateBackup(p, archive, account, &id); err != nil {
		return err
	}
	if err = checkOfflineUID(id.uid); err != nil {
		return err
	}
	return execute(p, true, rootIdentity)
}

func execute(p PlanData, rollback bool, locked unix.Stat_t) error {
	root, err := openAbsoluteDir(p.Archive, false)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(root) }()
	current, err := stat(root)
	if err != nil || current.Dev != locked.Dev || current.Ino != locked.Ino || uint64(current.Dev) != p.RootDev || current.Ino != p.RootIno {
		return errors.New("locked archive identity changed")
	}
	if err = inspect(p, root); err != nil {
		return err
	}
	expected := make(map[string]Metadata, len(p.Entries))
	for _, e := range p.Entries {
		expected[e.Path] = e
	}
	// Apply narrows the root first. Rollback restores it last, but may already
	// expose legacy shared descendants; keep every writer and session offline.
	if rollback {
		for i := len(p.Entries) - 1; i >= 1; i-- {
			if err = change(root, p.Entries[i], true, expected); err != nil {
				return err
			}
		}
		if err = change(root, p.Entries[0], true, expected); err != nil {
			return err
		}
		return verifyFinal(p, root, true, expected)
	}
	if err = change(root, p.Entries[0], false, expected); err != nil {
		return err
	}
	for i := 1; i < len(p.Entries); i++ {
		if err = change(root, p.Entries[i], false, expected); err != nil {
			return err
		}
	}
	return verifyFinal(p, root, false, expected)
}

func verifyFinal(p PlanData, root int, rollback bool, expected map[string]Metadata) error {
	if err := inspect(p, root); err != nil {
		return err
	}
	for _, e := range p.Entries {
		if strings.Contains(e.Path, "/.") {
			continue
		}
		fd, parent, _, st, err := openEntry(root, e.Path, expected)
		if err != nil {
			return err
		}
		if fd != root {
			_ = unix.Close(fd)
		}
		if parent >= 0 && parent != root {
			_ = unix.Close(parent)
		}
		uid, gid, mode := e.DesiredUID, e.DesiredGID, e.DesiredMode
		if rollback {
			uid, gid, mode = e.UID, e.GID, e.Mode
		}
		if st.Uid != uid || st.Gid != gid || st.Mode&07777 != mode {
			return fmt.Errorf("recording final metadata mismatch: %s", e.Path)
		}
	}
	return nil
}
