package recording

import (
	"context"
	"fmt"
	"goBastion/internal/telemetry"
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
func Publish(archive, source, relative string, uid int) (resultErr error) {
	if uid == -1 {
		uid = os.Geteuid()
	}
	_, span := telemetry.Start(context.Background(), "recording.publish", telemetry.Component("recording"))
	defer func() {
		if resultErr != nil {
			span.Failure()
		} else {
			span.Success()
		}
		span.End()
	}()

	if !filepath.IsLocal(relative) {
		return fmt.Errorf("invalid archive destination")
	}
	archiveDir, err := openArchiveDirectory(archive, ".", uid)
	if err != nil {
		return err
	}
	defer func() { _ = archiveDir.Close() }()
	dir, err := openArchiveSubdirectory(archiveDir, filepath.Dir(relative), uid)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	stageParent := archiveDir
	if os.Geteuid() != 0 {
		stageParent = dir
	}
	stagingName := ".publish-" + uuid.NewString()
	// Root stages below the trusted archive; sessions stage under their held
	// private server directory, inheriting the auditor group and setgid bit.
	anchored := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), stageParent.Fd())
	stagingPath := filepath.Join(anchored, stagingName)
	if err := os.Mkdir(stagingPath, 0700); err != nil {
		return err
	}
	stageFD, err := unix.Openat(int(stageParent.Fd()), stagingName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if err := ValidateNoACL(stageFD); err != nil {
		_ = unix.Close(stageFD)
		return err
	}
	stageAnchor := os.NewFile(uintptr(stageFD), "publication-staging")
	defer func() { _ = stageAnchor.Close() }()
	staging, err := os.OpenRoot(fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), stageFD))
	if err != nil {
		return err
	}
	defer func() { _ = staging.Close() }()
	info, err := staging.Stat(".")
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSticky != 0 {
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
	if st, err := dir.Stat(); err == nil {
		if stat, ok := st.Sys().(*syscall.Stat_t); ok {
			gid = int(stat.Gid)
		}
	}
	outInfo, err := out.Stat()
	if err != nil {
		return err
	}
	outStat, ok := outInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("invalid publication file identity")
	}
	if int(outStat.Uid) != uid || int(outStat.Gid) != gid {
		if err := out.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err := ValidateNoACL(int(out.Fd())); err != nil {
		return err
	}
	if err := out.Chmod(0640); err != nil {
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
