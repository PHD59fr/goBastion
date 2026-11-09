package sync

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils/validation"
)

func (s *Syncer) useSecureSSH() bool {
	_, linux := s.os.(*osadapter.LinuxAdapter)
	return os.Geteuid() == 0 && linux
}

// secureSSHDir anchors every user-controlled path component before use. The
// returned descriptor refers to the checked directory even if it is renamed.
func (s *Syncer) secureSSHDir(u models.User) (int, int, int, error) {
	if !validation.IsValidManagedUsername(u.Username) || u.Username != filepath.Base(u.Username) {
		return -1, 0, 0, fmt.Errorf("invalid username")
	}
	account, err := s.lookupUser(u.Username)
	if err != nil {
		return -1, 0, 0, fmt.Errorf("lookup OS user: %w", err)
	}
	uid64, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid64 < 1000 || uid64 >= 65000 {
		return -1, 0, 0, fmt.Errorf("invalid OS user ID")
	}
	gid64, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return -1, 0, 0, fmt.Errorf("invalid OS group ID")
	}
	uid, gid := int(uid64), int(gid64)
	base := config.Get().Paths.HomeBaseDir
	if !filepath.IsAbs(base) {
		return -1, 0, 0, fmt.Errorf("home base must be absolute")
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, 0, err
	}
	defer func() { _ = unix.Close(root) }()
	baseFD, err := openTrustedBaseFrom(root, strings.TrimPrefix(filepath.Clean(base), "/"), 0)
	if err != nil {
		return -1, 0, 0, err
	}
	defer func() { _ = unix.Close(baseFD) }()
	return secureSSHDirFrom(baseFD, u.Username, uid, gid, 0)
}

func openTrustedBaseFrom(root int, path string, uid uint32) (int, error) {
	fd, err := unix.FcntlInt(uintptr(root), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := checkSSHDir(fd, uid, true); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		if part == "." || part == ".." {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("invalid home base component")
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open home base component: %w", err)
		}
		fd = next
		if err := checkSSHDir(fd, uid, true); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("home base component: %w", err)
		}
	}
	return fd, nil
}

func secureSSHDirAt(base, name string, uid, gid int, trustedUID uint32) (int, int, int, error) {
	root, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, 0, fmt.Errorf("open home base: %w", err)
	}
	defer func() { _ = unix.Close(root) }()
	return secureSSHDirFrom(root, name, uid, gid, trustedUID)
}

func secureSSHDirFrom(root int, name string, uid, gid int, trustedUID uint32) (int, int, int, error) {
	if err := checkSSHDir(root, trustedUID, true); err != nil {
		return -1, 0, 0, fmt.Errorf("home base: %w", err)
	}
	home, err := unix.Openat(root, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, 0, fmt.Errorf("open home: %w", err)
	}
	defer func() { _ = unix.Close(home) }()
	if err := checkSSHDir(home, uint32(uid), true); err != nil {
		return -1, 0, 0, fmt.Errorf("home: %w", err)
	}
	// mkdir runs with the account's privileges, so a rename race cannot make
	// root transfer ownership of an attacker-selected directory.
	if err := mkdirSSHAsUser(home, uid, gid); err != nil {
		// It may already exist (or have been created concurrently); opening and
		// validating it below decides whether it is safe to use.
		var st unix.Stat_t
		if statErr := unix.Fstatat(home, ".ssh", &st, unix.AT_SYMLINK_NOFOLLOW); statErr != nil {
			return -1, 0, 0, fmt.Errorf("create ssh directory: %w", err)
		}
	}
	dir, err := unix.Openat(home, ".ssh", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, 0, fmt.Errorf("open ssh directory: %w", err)
	}
	fail := func(err error) (int, int, int, error) { _ = unix.Close(dir); return -1, 0, 0, err }
	if err := checkSSHDir(dir, uint32(uid), true); err != nil {
		return fail(fmt.Errorf("ssh directory: %w", err))
	}
	return dir, uid, gid, nil
}

func mkdirSSHAsUser(home, uid, gid int) error {
	dup, err := unix.FcntlInt(uintptr(home), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dup), "home")
	defer func() { _ = f.Close() }()
	cmd := exec.Command("/bin/mkdir", "-m", "0700", "--", "/proc/self/fd/3/.ssh")
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{}
	if os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: false}}
	} else if os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("cannot create SSH directory for another user")
	}
	return cmd.Run()
}

func checkSSHDir(fd int, uid uint32, noWrite bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || (noWrite && st.Mode&0022 != 0) {
		return fmt.Errorf("unsafe directory ownership or mode")
	}
	return nil
}

func publishSSHFile(dir, uid, gid int, name string, data []byte) error {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	tmp := ".gobastion-" + hex.EncodeToString(b[:])
	fd, err := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(dir, tmp, 0) }()
	f := os.NewFile(uintptr(fd), tmp)
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 0600); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := unix.Fstatat(dir, tmp, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino || named.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("temporary SSH file replaced")
	}
	if err := unix.Renameat(dir, tmp, dir, name); err != nil {
		return err
	}
	return unix.Fsync(dir)
}
