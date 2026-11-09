package recording

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const AuditorGroup = "gobastion-auditors"

func recordingGroupID(name string) (int, error) {
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("recording group %s is unavailable", name)
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || gid == 0 || strconv.FormatUint(gid, 10) != group.Gid || int(gid) < 0 {
		return 0, fmt.Errorf("invalid recording group ID")
	}
	return int(gid), nil
}

// ValidateArchive checks recording archive root integrity and the supported
// storage layout. Unsafe ownership, permissions, ACLs, or unsupported legacy
// layouts cause a failure.
func ValidateArchive(archive string) error {
	dir, err := openArchiveDirectory(archive, ".", os.Geteuid())
	if err != nil {
		return err
	}
	return dir.Close()
}

// openArchiveDirectory walks every component without following symlinks. A
// production archive is root:gobastion 0751; account namespaces are provisioned
// by root and cannot be reserved by sessions. Self-owned 0700 archives support
// standalone private recording without enabling a shared-directory fallback.
func openArchiveDirectory(archive, relative string, owner int) (*os.File, error) {
	if owner < 0 || !filepath.IsAbs(archive) || (relative != "." && !filepath.IsLocal(relative)) {
		return nil, fmt.Errorf("invalid recording directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) { _ = unix.Close(fd); return nil, err }
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(archive), "/"), "/")
	for index, part := range parts {
		if part == "" {
			continue
		}
		if index == len(parts)-1 && os.Geteuid() != 0 {
			if err := unix.Mkdirat(fd, part, 0700); err != nil && err != unix.EEXIST {
				return fail(err)
			}
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail(fmt.Errorf("open recording archive: %w", err))
		}
		_ = unix.Close(fd)
		fd = next
		if index < len(parts)-1 {
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil {
				return fail(err)
			}
			if (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0) {
				return fail(fmt.Errorf("untrusted recording archive ancestor"))
			}
		}
	}
	base := os.NewFile(uintptr(fd), "recording-archive")
	if _, err := archiveIsolation(base); err != nil {
		_ = base.Close()
		return nil, err
	}
	defer func() { _ = base.Close() }()
	return openArchiveSubdirectory(base, relative, owner)
}

// archiveIsolation identifies the two supported layouts. Shared legacy trees
// require an explicit offline migration; opening them never changes permissions.
func archiveIsolation(base *os.File) (bool, error) {
	if err := ValidateNoACL(int(base.Fd())); err != nil {
		return false, err
	}

	var st unix.Stat_t
	if err := unix.Fstat(int(base.Fd()), &st); err != nil {
		return false, err
	}
	if st.Uid == uint32(os.Geteuid()) && st.Mode&07777 == 0700 {
		return false, nil
	}
	shared, err := recordingGroupID("gobastion")
	if err != nil {
		return false, err
	}
	if st.Uid != 0 || st.Gid != uint32(shared) || st.Mode&07777 != 0751 {
		return false, fmt.Errorf("unsafe recording archive owner or permissions; provision an isolated archive")
	}
	auditors, err := recordingGroupID(AuditorGroup)
	if err != nil {
		return false, err
	}
	if auditors == shared {
		return false, fmt.Errorf("recording auditor group must differ from the shared bastion group")
	}
	return true, nil
}

func validRecordingComponent(part string) bool {
	return part != "" && part != "." && part != ".." && !strings.HasPrefix(part, ".")
}

func openArchiveSubdirectory(base *os.File, relative string, owner int) (*os.File, error) {
	if relative != "." && !filepath.IsLocal(relative) {
		return nil, fmt.Errorf("invalid recording parent")
	}
	isolated, err := archiveIsolation(base)
	if err != nil {
		return nil, err
	}
	gid := os.Getegid()
	if isolated {
		gid, err = recordingGroupID(AuditorGroup)
		if err != nil {
			return nil, err
		}
	}
	fd, err := unix.FcntlInt(base.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) { _ = unix.Close(fd); return nil, err }
	if relative != "." {
		parts := strings.Split(relative, string(filepath.Separator))
		if isolated && len(parts) > 2 {
			return fail(fmt.Errorf("invalid recording parent depth"))
		}
		for index, part := range parts {
			if !validRecordingComponent(part) {
				return fail(fmt.Errorf("invalid recording parent component"))
			}
			if isolated {
				if index == 0 {
					uid, err := recordingUsernameUID(part)
					if err != nil || uid != owner {
						return fail(fmt.Errorf("recording account identity mismatch"))
					}
				} else if os.Geteuid() == 0 {
					if err := createIsolatedDirectory(base, fd, part, owner, gid); err != nil {
						return fail(err)
					}
				} else {
					// mkdir inherits the auditor group and setgid bit. Create with the
					// final mode so a restrictive process umask cannot produce a legacy
					// 02700 directory that breaks validation. The thread-local umask swap
					// avoids chmod by owners who are not members of the auditor group.
					runtime.LockOSThread()
					oldMask := unix.Umask(0)
					err := unix.Mkdirat(fd, part, 02750)
					unix.Umask(oldMask)
					runtime.UnlockOSThread()
					if err != nil && err != unix.EEXIST {
						return fail(err)
					}
				}
			} else if err := unix.Mkdirat(fd, part, 0700); err != nil && err != unix.EEXIST {
				return fail(err)
			}
			next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return fail(fmt.Errorf("open recording parent: %w", err))
			}
			_ = unix.Close(fd)
			fd = next
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil {
				return fail(err)
			}
			if err := ValidateNoACL(fd); err != nil {
				return fail(err)
			}
			expectedMode := uint32(0700)
			if isolated {
				expectedMode = 02750
			}
			modeMatches := st.Mode&07777 == expectedMode
			if !isolated {
				// The held 0700 archive already excludes every other UID. Preserve
				// existing non-writable group read/traverse on its nested directories.
				modeMatches = st.Mode&07777 == 0700 || st.Mode&07777 == 0750
			}
			if st.Uid != uint32(owner) || !modeMatches || (isolated && st.Gid != uint32(gid)) {
				return fail(fmt.Errorf("unsafe recording directory owner or permissions"))
			}
		}
	}
	return os.NewFile(uintptr(fd), "recording-directory"), nil
}

// createIsolatedDirectory initializes only a new inode beneath the trusted root
// and publishes it exclusively. Existing account-owned trees are never chowned.
func createIsolatedDirectory(base *os.File, parent int, name string, uid, gid int) error {
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return nil
	} else if err != unix.ENOENT {
		return err
	}
	stage := ".provision-" + uuid.NewString()
	if err := unix.Mkdirat(int(base.Fd()), stage, 0700); err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(int(base.Fd()), stage, unix.AT_REMOVEDIR) }()
	fd, err := unix.Openat(int(base.Fd()), stage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 02750); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	if err := unix.Renameat2(int(base.Fd()), stage, parent, name, unix.RENAME_NOREPLACE); err != nil && err != unix.EEXIST {
		return err
	}
	return unix.Fsync(parent)
}
