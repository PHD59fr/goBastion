package recording

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	streamPollInterval = 100 * time.Millisecond
	streamStartTimeout = 10 * time.Second
)

type flushWriter interface {
	io.Writer
	Flush() error
}

// StreamRaw copies a recorder's growing file into a compressed sink. A failed
// read or write stops the client immediately, before an unrecorded session can
// continue. Flush each block so a full recording volume is detected while the
// client is still active, rather than only when the session ends.
func StreamRaw(path string, sink flushWriter, recorderDone, abort <-chan struct{}, stopClient func()) error {
	fail := func(err error) error {
		if stopClient != nil {
			stopClient()
		}
		return err
	}
	poll := time.NewTicker(streamPollInterval)
	defer poll.Stop()
	start := time.NewTimer(streamStartTimeout)
	defer start.Stop()
	var source *os.File
waitForRecorder:
	for {
		var err error
		source, err = openRawRecording(path)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fail(fmt.Errorf("open raw recording: %w", err))
		}
		select {
		case <-abort:
			return fail(errors.New("recording stream aborted before recorder completion"))
		case <-recorderDone:
			// The recorder may have created the file just before the done
			// channel closed, after our previous failed open.
			if source, err = openRawRecording(path); err == nil {
				break waitForRecorder
			}
			return fail(errors.New("recorder exited without creating a recording"))
		case <-start.C:
			if source, err = openRawRecording(path); err == nil {
				break waitForRecorder
			}
			return fail(errors.New("recorder did not create a recording before deadline"))
		case <-poll.C:
		}
	}
	defer func() { _ = source.Close() }()
	return streamOpenedRaw(source, sink, recorderDone, abort, poll.C, fail)
}

func openRawRecording(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || int(owner.Uid) != os.Geteuid() {
		_ = file.Close()
		return nil, errors.New("raw recording must be a regular file owned by the recorder")
	}
	return file, nil
}

func streamOpenedRaw(source io.Reader, sink flushWriter, recorderDone, abort <-chan struct{}, poll <-chan time.Time, fail func(error) error) error {
	buf := make([]byte, 4096)
	recorderFinished := false
	for {
		select {
		case <-abort:
			return fail(errors.New("recording stream aborted before recorder completion"))
		default:
		}
		n, readErr := source.Read(buf)
		if n > 0 {
			written, writeErr := sink.Write(buf[:n])
			if writeErr == nil && written != n {
				writeErr = io.ErrShortWrite
			}
			if writeErr != nil {
				return fail(fmt.Errorf("compress raw recording: %w", writeErr))
			}
			if err := sink.Flush(); err != nil {
				return fail(fmt.Errorf("flush compressed recording: %w", err))
			}
		}
		if readErr == nil {
			continue
		}
		if !errors.Is(readErr, io.EOF) {
			return fail(fmt.Errorf("read raw recording: %w", readErr))
		}
		// A writer can append its final bytes after this EOF and finish before
		// the select below. Once completion is observed, read to EOF once more.
		if recorderFinished {
			return nil
		}
		select {
		case <-abort:
			return fail(errors.New("recording stream aborted before recorder completion"))
		case <-recorderDone:
			recorderFinished = true
		case <-poll:
		}
	}
}
