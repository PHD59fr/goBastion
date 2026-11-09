package recording

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// SSHSpool keeps capture operations anchored to the private directory opened
// at creation. Path is diagnostic only; WorkPath requires procfs access to
// the supervisor's descriptor from the recorder process.
type SSHSpool struct {
	Path     string
	WorkPath string
	dir      *os.File
	parent   *os.File
	name     string
}

func NewSSHSpool(archive, relative string) (*SSHSpool, error) {
	parent, err := openArchiveDirectory(archive, relative, os.Geteuid())
	if err != nil {
		return nil, err
	}
	return newSSHSpoolAt(parent, filepath.Join(archive, relative))
}

// Ownership of parent is transferred to the spool, including on failure.
func newSSHSpoolAt(parent *os.File, diagnostic string) (*SSHSpool, error) {
	parentFD := int(parent.Fd())
	name := ".ssh-record-" + uuid.NewString()
	if err := unix.Mkdirat(parentFD, name, 0700); err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("create SSH spool: %w", err)
	}
	fd, err := openSSHSpool(parentFD, name)
	if err != nil {
		_ = parent.Close()
		return nil, err
	}
	anchor := os.NewFile(uintptr(fd), name)
	return &SSHSpool{Path: filepath.Join(diagnostic, name), WorkPath: fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd), dir: anchor, parent: parent, name: name}, nil
}

func openSSHSpool(parentFD int, name string) (int, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open SSH spool: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&07777&^unix.S_ISGID != 0700 {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("invalid SSH spool owner or permissions")
	}
	// A setgid parent propagates that bit even when mkdir requested 0700.
	if err := unix.Fchmod(fd, 0700); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// Close optionally removes direct spool entries through the held directory.
// The isolated, ownership-checked production parent excludes other session
// UIDs. A detected rename leaves the replacement untouched.
func (s *SSHSpool) Close(clean bool) error {
	if s == nil || s.dir == nil {
		return nil
	}
	var cleanupErr error
	if clean {
		entries, err := s.dir.ReadDir(-1)
		if err != nil {
			cleanupErr = err
		} else {
			for _, entry := range entries {
				if err := unix.Unlinkat(int(s.dir.Fd()), entry.Name(), 0); err != nil {
					cleanupErr = errors.Join(cleanupErr, err)
				}
			}
		}
		if cleanupErr == nil {
			var opened, named unix.Stat_t
			if err := unix.Fstat(int(s.dir.Fd()), &opened); err != nil {
				cleanupErr = err
			} else if err := unix.Fstatat(int(s.parent.Fd()), s.name, &named, unix.AT_SYMLINK_NOFOLLOW); err == nil && opened.Dev == named.Dev && opened.Ino == named.Ino {
				cleanupErr = unix.Unlinkat(int(s.parent.Fd()), s.name, unix.AT_REMOVEDIR)
			}
		}
	}
	err := errors.Join(cleanupErr, s.dir.Close(), s.parent.Close())
	s.dir = nil
	return err
}
