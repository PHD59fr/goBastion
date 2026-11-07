package recording

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// Publish copies into a private staging directory on the destination volume,
// then commits with an exclusive hard link. A killed copier never exposes a
// partial final archive; open directory descriptors prevent symlink path swaps.
func Publish(archive, source, relative string, uid int) error {
	root, err := os.OpenRoot(archive)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if !filepath.IsLocal(relative) {
		return fmt.Errorf("invalid archive destination")
	}
	parent := filepath.Dir(relative)
	if err := root.MkdirAll(parent, 0770); err != nil {
		return err
	}
	dir, err := root.Open(parent)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Chmod(0770 | os.ModeSetgid); err != nil {
		return err
	}
	stagingName := ".publish-" + uuid.NewString()
	// Use the already-open destination directory for staging as well.
	anchored := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), dir.Fd())
	stagingPath := filepath.Join(anchored, stagingName)
	if err := os.Mkdir(stagingPath, 0700); err != nil {
		return err
	}
	staging, err := os.OpenRoot(stagingPath)
	if err != nil {
		return err
	}
	defer func() { _ = staging.Close() }()
	info, err := staging.Stat(".")
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("invalid publication staging owner")
	}
	lock, err := staging.OpenFile(".lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	defer func() { _ = staging.Remove("recording.gz"); _ = staging.Remove(".lock"); _ = os.Remove(stagingPath) }()
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := staging.OpenFile("recording.gz", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	gid := -1
	if st, err := root.Stat("."); err == nil {
		if stat, ok := st.Sys().(*syscall.Stat_t); ok {
			gid = int(stat.Gid)
		}
	}
	if err := out.Chown(uid, gid); err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	stageDir, err := staging.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = stageDir.Close() }()
	if err := unix.Linkat(int(stageDir.Fd()), "recording.gz", int(dir.Fd()), filepath.Base(relative), 0); err != nil {
		return err
	}
	return dir.Sync()
}
