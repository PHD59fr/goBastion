package dbsandbox

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type activityKey struct{}

// WithActivity tracks DB traffic and terminal I/O without replacing the
// supervisor's terminal descriptors. The worker reports activity, never secrets.
func WithActivity(ctx context.Context, touch func()) context.Context {
	return context.WithValue(ctx, activityKey{}, touch)
}

type activityConn struct {
	net.Conn
	touch func()
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

type activityReader struct {
	io.Reader
	touch func()
}

func (r activityReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 && r.touch != nil {
		r.touch()
	}
	return n, err
}

type activityWriter struct {
	io.Writer
	touch func()
}

func (w activityWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 && w.touch != nil {
		w.touch()
	}
	return n, err
}

func activityNotifier(fd int) func() {
	var last atomic.Int64
	return func() {
		now, previous := time.Now().UnixNano(), last.Load()
		if now-previous < int64(25*time.Millisecond) || !last.CompareAndSwap(previous, now) {
			return
		}
		// Activity may be coalesced when the trusted control socket is full.
		// Never block terminal I/O waiting for the supervisor to consume it.
		_ = unix.Sendmsg(fd, []byte{'A'}, nil, nil, unix.MSG_DONTWAIT)
	}
}
