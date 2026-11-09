package sync

import (
	"errors"
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// Pending revocations outlive failed helpers. /run is sufficient across reboot:
// process credentials cannot survive reboot, unlike a failed delgroup/kill pair.
type auditorJournal struct {
	root  *os.Root
	owner uint32
}

func openAuditorJournal() (*auditorJournal, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("auditor revocation journal requires root")
	}
	fd, err := unix.Open("/run", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Mode&0022 != 0 {
		return nil, fmt.Errorf("unsafe runtime directory")
	}
	for _, name := range []string{"gobastion", "recording-revocations"} {
		if err = unix.Mkdirat(fd, name, 0700); err != nil && err != unix.EEXIST {
			return nil, err
		}
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		if e = unix.Fstat(next, &st); e != nil || st.Uid != 0 || st.Mode&07777 != 0700 {
			_ = unix.Close(next)
			return nil, fmt.Errorf("unsafe auditor revocation journal")
		}
		_ = unix.Close(fd)
		fd = next
	}
	root, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, err
	}
	return &auditorJournal{root: root, owner: 0}, nil
}

func (j *auditorJournal) close() error { return j.root.Close() }
func (j *auditorJournal) sync() error {
	f, err := j.root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}
func (j *auditorJournal) read(name string, temporary bool) (string, error) {
	f, err := j.root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	maxLinks := uint64(1)
	if temporary {
		maxLinks = 2
	}
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != j.owner || uint64(st.Nlink) > maxLinks || info.Size() > 32 {
		return "", fmt.Errorf("unsafe auditor revocation marker")
	}
	data, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return "", err
	}
	if temporary {
		return "", nil
	}
	raw := strings.TrimSuffix(string(data), "\n")
	uid, err := canonicalID(raw)
	if err != nil || uid < 1000 || uid >= 65000 || string(data) != raw+"\n" {
		return "", fmt.Errorf("invalid auditor revocation marker")
	}
	return raw, nil
}
func (j *auditorJournal) load() (map[string]string, error) {
	f, err := j.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := f.ReadDir(100001)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 100000 {
		return nil, fmt.Errorf("too many pending auditor revocations")
	}
	// Complete a publication interrupted after link but before temp unlink, before
	// requiring every final marker to have exactly one link.
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".pending-") {
			if _, err = j.read(entry.Name(), true); err != nil {
				return nil, err
			}
			if err = j.root.Remove(entry.Name()); err != nil {
				return nil, err
			}
		}
	}
	pending := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".pending-") {
			continue
		}
		if !canonicalAccountName(name) {
			return nil, fmt.Errorf("invalid auditor revocation marker name")
		}
		uid, e := j.read(name, false)
		if e != nil {
			return nil, e
		}
		pending[name] = uid
	}
	return pending, j.sync()
}
func (j *auditorJournal) mark(name, uid string) error {
	if !canonicalAccountName(name) {
		return fmt.Errorf("invalid auditor revocation account")
	}
	n, err := canonicalID(uid)
	if err != nil || n < 1000 || n >= 65000 {
		return fmt.Errorf("invalid auditor revocation ID")
	}
	if existing, e := j.read(name, false); e == nil {
		if existing != uid {
			return fmt.Errorf("auditor revocation identity changed")
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	tmp := ".pending-" + uuid.NewString()
	f, err := j.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = j.root.Remove(tmp) }()
	if _, err = f.WriteString(uid + "\n"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = j.root.Link(tmp, name); err != nil {
		return err
	}
	if err = j.root.Remove(tmp); err != nil {
		return err
	}
	return j.sync()
}
func (j *auditorJournal) clear(name, uid string) error {
	existing, err := j.read(name, false)
	if err != nil {
		return err
	}
	if existing != uid {
		return fmt.Errorf("auditor revocation identity changed")
	}
	if err = j.root.Remove(name); err != nil {
		return err
	}
	return j.sync()
}

// Resolve a pending UID again before signalling it. Never kill a recycled UID.
func (s *Syncer) pendingAuditorAccount(name, uid string, gid uint64) (*osuser.User, error) {
	account, err := s.auditorAccount(name, gid)
	if err == nil {
		if account.Uid != uid {
			return nil, fmt.Errorf("pending auditor UID changed")
		}
		return account, nil
	}
	var unknown osuser.UnknownUserError
	if !errors.As(err, &unknown) || s.lookupUID == nil {
		return nil, err
	}
	_, uidErr := s.lookupUID(uid)
	var unknownID osuser.UnknownUserIdError
	if errors.As(uidErr, &unknownID) {
		return &osuser.User{Username: name, Uid: uid}, nil
	}
	return nil, fmt.Errorf("pending auditor UID unavailable or reassigned")
}
