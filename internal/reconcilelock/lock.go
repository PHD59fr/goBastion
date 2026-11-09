// Package reconcilelock serializes privileged reconciliation on one host.
package reconcilelock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const Timeout = 30 * time.Second

// Acquire obtains the fixed root-owned reconciliation lock. The lock file must
// never be removed while any process may use it: flock is tied to the inode.
func Acquire(ctx context.Context) (func() error, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("reconciliation lock requires root")
	}
	return acquire(ctx, "/run", 0)
}

func acquire(ctx context.Context, base string, uid uint32) (func() error, error) {
	d, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open lock base: %w", err)
	}
	defer func() { _ = unix.Close(d) }()
	if err = checkDir(d, uid); err != nil {
		return nil, fmt.Errorf("lock base: %w", err)
	}
	if err = unix.Mkdirat(d, "gobastion", 0700); err != nil && err != unix.EEXIST {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	dir, err := unix.Openat(d, "gobastion", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open lock directory: %w", err)
	}
	defer func() { _ = unix.Close(dir) }()
	if err = checkDir(dir, uid); err != nil {
		return nil, fmt.Errorf("lock directory: %w", err)
	}
	fd, err := unix.Openat(dir, "reconcile.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open reconciliation lock: %w", err)
	}
	fail := func(err error) (func() error, error) { _ = unix.Close(fd); return nil, err }
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return fail(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uid || st.Mode&0777 != 0600 || st.Nlink != 1 {
		return fail(fmt.Errorf("insecure reconciliation lock file"))
	}
	for {
		if err = ctx.Err(); err != nil {
			return fail(fmt.Errorf("reconciliation lock: %w", err))
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN && err != unix.EINTR {
			return fail(fmt.Errorf("acquire reconciliation lock: %w", err))
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fail(fmt.Errorf("reconciliation lock: %w", ctx.Err()))
		case <-timer.C:
		}
	}
	var current unix.Stat_t
	if err = unix.Fstatat(dir, "reconcile.lock", &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || current.Dev != st.Dev || current.Ino != st.Ino || current.Nlink != 1 {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return fail(fmt.Errorf("reconciliation lock inode changed"))
	}
	return func() error {
		return errors.Join(unix.Flock(fd, unix.LOCK_UN), unix.Close(fd))
	}, nil
}

func checkDir(fd int, uid uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Mode&0022 != 0 {
		return fmt.Errorf("insecure owner or permissions (uid=%d mode=%#o, expected uid=%d)", st.Uid, st.Mode, uid)
	}
	return nil
}
