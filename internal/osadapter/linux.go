package osadapter

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/validation"
	"golang.org/x/sys/unix"
)

// LinuxAdapter is the real implementation of SystemAdapter for Linux.
type LinuxAdapter struct{}

// NewLinuxAdapter returns the Linux SystemAdapter.
func NewLinuxAdapter() SystemAdapter {
	return &LinuxAdapter{}
}

func managedName(name string) (string, error) {
	if !validation.IsValidManagedUsername(name) {
		return "", errors.New("invalid or reserved managed username")
	}
	return name, nil
}

func (l *LinuxAdapter) syncUser(name string) error {
	if _, err := l.ExecCommand("/usr/bin/sudo", "-n", "/usr/local/sbin/gobastion-sync-user", name); err != nil {
		return fmt.Errorf("privileged DB-backed user sync failed: %w", err)
	}
	return nil
}

func canonicalLocalUser(name string) (*user.User, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	if account == nil || account.Username != name {
		return nil, errors.New("noncanonical local account name")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 1000 || uid >= 65000 || strconv.Itoa(uid) != account.Uid {
		return nil, errors.New("local account UID outside managed range")
	}
	byID, err := user.LookupId(account.Uid)
	if err != nil || byID == nil || byID.Username != name || byID.Uid != account.Uid {
		return nil, errors.New("noncanonical local account UID")
	}
	return account, nil
}

// removeLegacySudoers only unlinks a checked per-user file. It never writes
// a role grant: the global group policy delegates fresh DB-backed root sync.
func removeLegacySudoers(name string) error {
	if !validation.IsValidManagedUsername(name) {
		return errors.New("protected sudoers name")
	}
	etc, err := unix.Open("/etc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(etc) }()
	var st unix.Stat_t
	if err = unix.Fstat(etc, &st); err != nil || st.Uid != 0 || st.Mode&0022 != 0 {
		return errors.New("unsafe /etc identity")
	}
	dir, err := unix.Openat(etc, "sudoers.d", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dir) }()
	if err = unix.Fstat(dir, &st); err != nil || st.Uid != 0 || st.Mode&0022 != 0 {
		return errors.New("unsafe sudoers directory identity")
	}
	if err = unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == unix.ENOENT {
		return nil
	} else if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0022 != 0 {
		return errors.New("unsafe legacy sudoers entry")
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "legacy-sudoers")
	defer func() { _ = f.Close() }()
	var opened unix.Stat_t
	if err = unix.Fstat(fd, &opened); err != nil || opened.Dev != st.Dev || opened.Ino != st.Ino || opened.Uid != 0 || opened.Nlink != 1 || opened.Mode&0022 != 0 || opened.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("legacy sudoers entry changed")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return err
	}
	if len(data) > 4096 || string(data) != legacySudoersPolicy(name) {
		return errors.New("unrecognized sudoers policy requires operator repair")
	}
	var current unix.Stat_t
	if err = unix.Fstatat(dir, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || current.Dev != opened.Dev || current.Ino != opened.Ino || current.Uid != 0 || current.Nlink != 1 || current.Mode&0022 != 0 || current.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("legacy sudoers entry changed before removal")
	}
	if err = unix.Unlinkat(dir, name, 0); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

// Only this exact historical goBastion template is ours to remove. A matching
// filename alone never authorizes deleting an operator's independent policy.
func legacySudoersPolicy(name string) string {
	var policy strings.Builder
	for _, helper := range []string{"gobastion-adduser", "gobastion-passwd-delete", "gobastion-deluser", "gobastion-chown-ssh", "gobastion-sudoers"} {
		fmt.Fprintf(&policy, "%s ALL=(root) NOPASSWD: /usr/local/sbin/%s *\n", name, helper)
	}
	return policy.String()
}

func (l *LinuxAdapter) CreateUser(username string) error {
	name, err := managedName(username)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return l.syncUser(name)
	}
	// Root is already inside the node-local reconciliation lock. Never adopt
	// a pre-existing account with a missing home as a side effect of creation.
	if _, err = canonicalLocalUser(name); err == nil {
		return errors.New("existing local account requires operator reconciliation")
	}
	var unknown user.UnknownUserError
	if !errors.As(err, &unknown) {
		return fmt.Errorf("cannot prove local account absence: %w", err)
	}
	if _, err = l.ExecCommand("/usr/sbin/adduser", "--disabled-password", "--gecos", "", name); err != nil {
		return fmt.Errorf("native user creation failed: %w", err)
	}
	if _, err = canonicalLocalUser(name); err != nil {
		return fmt.Errorf("created local account identity invalid: %w", err)
	}
	if _, err = l.ExecCommand("/usr/sbin/addgroup", name, "gobastion"); err != nil {
		return fmt.Errorf("native bastion group assignment failed: %w", err)
	}
	if _, err = l.ExecCommand("/usr/bin/passwd", "-d", name); err != nil {
		return fmt.Errorf("native password disable failed: %w", err)
	}
	return nil
}

func (l *LinuxAdapter) DeleteUser(username string) error {
	name, err := managedName(username)
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("root account deletion is forbidden; use DB-backed retirement")
	}
	return l.syncUser(name)
}

func (l *LinuxAdapter) UpdateSudoers(user *models.User) error {
	if user == nil {
		return errors.New("missing managed account")
	}
	name, err := managedName(user.Username)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return l.syncUser(name)
	}
	return removeLegacySudoers(name)
}

func (l *LinuxAdapter) TerminateUserSessions(username string) error {
	name, err := managedName(username)
	if err != nil {
		return err
	}
	account, err := canonicalLocalUser(name)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	// The sync process runs as root. Kill the whole account's process set,
	// including SSH/ttyrec children, so an established connection cannot survive.
	err = exec.Command("/usr/bin/pkill", "-KILL", "-u", strconv.Itoa(uid)).Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil // No processes remain.
	}
	return err
}

func (l *LinuxAdapter) ChownDir(user models.User, dir string) error {
	name, err := managedName(user.Username)
	if err != nil {
		return err
	}
	expected := filepath.Join(config.Get().Paths.HomeBaseDir, name, ".ssh")
	if dir != expected {
		return errors.New("ownership request outside managed SSH directory")
	}
	return l.syncUser(name)
}

func (l *LinuxAdapter) ExecCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (l *LinuxAdapter) UserHomeExists(username string) bool {
	if !validation.IsValidManagedUsername(username) {
		return false
	}
	userDir := filepath.Join(config.Get().Paths.HomeBaseDir, username)
	_, err := os.Stat(userDir)
	return err == nil
}
