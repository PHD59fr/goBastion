// Package recording manages recoverable session recordings outside client processes.
package recording

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

type Manifest struct {
	Destination string
	Raw         string
}

// Prepare holds a lock until finalization. The recorder inherits the same lock
// so a killed supervisor cannot make a still-running recording look abandoned.
func Prepare(spool, destination, raw string) (*os.File, error) {
	lock, err := os.OpenFile(filepath.Join(spool, ".lock"), os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, err
	}
	data, err := json.Marshal(Manifest{destination, filepath.Base(raw)})
	if err == nil {
		err = os.WriteFile(filepath.Join(spool, "manifest.json"), data, 0600)
	}
	if err == nil {
		var f *os.File
		f, err = os.OpenFile(filepath.Join(spool, "manifest.json"), os.O_RDWR, 0)
		if err == nil {
			err = f.Sync()
			_ = f.Close()
		}
	}
	if err == nil {
		var dir *os.File
		dir, err = os.Open(spool)
		if err == nil {
			err = dir.Sync()
			_ = dir.Close()
		}
	}

	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func ConfigureRecorder(cmd *exec.Cmd, lock *os.File) {
	cmd.ExtraFiles = append(cmd.ExtraFiles, lock)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGHUP}
	}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGHUP) }
	cmd.WaitDelay = 3 * time.Second
}

// Prefer the persistent archive volume. A temporary fallback still captures a
// session if the archive itself is unavailable; recovery also scans that fallback.
type DBSpool struct {
	Path, WorkPath string
	anchor         *os.File
}

func (s *DBSpool) Close() {
	if s.anchor != nil {
		_ = s.anchor.Close()
	}
}
func NewDBSpool(archive string) (*DBSpool, error) {
	if root, err := os.OpenRoot(archive); err == nil {
		defer func() { _ = root.Close() }()
		if err := root.Mkdir(".db-pending", 0700); err == nil || os.IsExist(err) {
			if pending, err := root.OpenRoot(".db-pending"); err == nil {
				defer func() { _ = pending.Close() }()
				if info, err := pending.Stat("."); err == nil && info.Mode().Perm() == 0700 {
					if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) == os.Geteuid() {
						name := "db-record-" + uuid.NewString()
						if err := pending.Mkdir(name, 0700); err == nil {
							if anchor, err := pending.Open(name); err == nil {
								path := filepath.Join(archive, ".db-pending", name)
								return &DBSpool{path, fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), anchor.Fd()), anchor}, nil
							}
						}
					}
				}
			}
		}
	}
	path, err := os.MkdirTemp("", "gobastion-db-record-")
	if err != nil {
		return nil, err
	}
	return &DBSpool{Path: path, WorkPath: path}, nil
}

func regular(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("recording entry is not a regular file")
	}
	return nil
}
