package logger

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// listenAudit holds an exclusive lock until after the listener has closed.
// The lock inode is permanent; removing it would allow competing collectors.
// Production supplies a root-owned directory under the trusted /run parent.
func listenAudit(directory string, uid uint32) (*net.UnixListener, func(), error) {
	dir, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(dir, &st); err != nil || st.Uid != uid || st.Mode&0022 != 0 {
		_ = unix.Close(dir)
		return nil, nil, errors.New("unsafe audit runtime directory")
	}
	lock, err := unix.Openat(dir, "collector.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		_ = unix.Close(dir)
		return nil, nil, err
	}
	release := func() { _ = unix.Close(lock); _ = unix.Close(dir) }
	fail := func(err error) (*net.UnixListener, func(), error) { release(); return nil, nil, err }
	if err := unix.Fstat(lock, &st); err != nil || st.Uid != uid || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 {
		return fail(errors.New("unsafe audit lifecycle lock"))
	}
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(fmt.Errorf("audit collector already running: %w", err))
	}
	var current unix.Stat_t
	if err := unix.Fstatat(dir, "collector.lock", &current, unix.AT_SYMLINK_NOFOLLOW); err != nil || current.Dev != st.Dev || current.Ino != st.Ino {
		return fail(errors.New("audit lifecycle lock inode changed"))
	}
	path := filepath.Join(directory, "audit.sock")
	err = unix.Fstatat(dir, "audit.sock", &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if st.Uid != uid || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			return fail(errors.New("unsafe existing audit socket"))
		}
		// Also preserve listeners created before lifecycle locking was introduced.
		conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return fail(errors.New("audit socket is still live"))
		}
		if !errors.Is(dialErr, unix.ECONNREFUSED) {
			return fail(errors.New("cannot establish audit socket is stale"))
		}
		if err := unix.Unlinkat(dir, "audit.sock", 0); err != nil {
			return fail(err)
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return fail(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	var once sync.Once
	return listener, func() { once.Do(func() { _ = listener.Close(); release() }) }, nil
}
