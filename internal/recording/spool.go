// Package recording manages recoverable session recordings outside client processes.
package recording

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	Encoding    string `json:",omitempty"`
}

const RecorderExitTimeout = 5 * time.Second

// Prepare holds a lock until finalization. The recorder inherits the same lock
// so a killed supervisor cannot make a still-running recording look abandoned.
func Prepare(spool, destination, raw string) (*os.File, error) {
	return PrepareCapture(spool, destination, raw, false)
}

// PrepareCapture records the output encoding before capture starts. Encrypted
// pending captures require explicit administrative recovery; they must never be
// silently republished as plaintext gzip after a restart or policy removal.
func PrepareCapture(spool, destination, raw string, encrypted bool) (*os.File, error) {
	lock, err := os.OpenFile(filepath.Join(spool, ".lock"), os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, err
	}
	manifest := Manifest{Destination: destination, Raw: filepath.Base(raw)}
	if encrypted {
		manifest.Encoding = "gobrec01"
	}
	data, err := json.Marshal(manifest)
	if err == nil {
		var f *os.File
		f, err = os.OpenFile(filepath.Join(spool, "manifest.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
		if err == nil {
			var n int
			n, err = f.Write(data)
			if err == nil && n != len(data) {
				err = io.ErrShortWrite
			}
			if err == nil {
				err = f.Sync()
			}
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
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

type RecorderCompletion struct {
	reader *os.File
	writer *os.File
}

// ConfigureRecorder gives the recorder both the spool exclusion lock and a
// separate completion pipe. The supervisor keeps the spool lock until after
// publication; only the completion pipe is closed to wait for descendants.
func ConfigureRecorder(cmd *exec.Cmd, lock *os.File) (*RecorderCompletion, error) {
	if cmd == nil || lock == nil {
		return nil, errors.New("recorder requires command and spool lock")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create recorder completion pipe: %w", err)
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, lock, writer)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGHUP}
	}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGHUP) }
	cmd.WaitDelay = 3 * time.Second
	return &RecorderCompletion{reader: reader, writer: writer}, nil
}

func (c *RecorderCompletion) Close() {
	if c == nil {
		return
	}
	if c.reader != nil {
		_ = c.reader.Close()
		c.reader = nil
	}
	if c.writer != nil {
		_ = c.writer.Close()
		c.writer = nil
	}
}

// Wait returns only after all processes that inherited the pipe have exited
// or closed it. The caller still holds the main spool lock during this wait.
func (c *RecorderCompletion) Wait(timeout time.Duration) error {
	if c == nil || c.reader == nil || c.writer == nil || timeout <= 0 {
		return errors.New("invalid recorder completion pipe or timeout")
	}
	defer c.Close()
	if err := c.writer.Close(); err != nil {
		return fmt.Errorf("close supervisor recorder pipe: %w", err)
	}
	c.writer = nil
	if err := c.reader.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set recorder completion deadline: %w", err)
	}
	var marker [1]byte
	n, err := c.reader.Read(marker[:])
	if n != 0 || err == nil {
		return errors.New("recorder completion pipe contained unexpected data")
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return fmt.Errorf("wait for recorder descendants: %w", err)
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
