package sessionlimit

import (
	"net"
	"sync/atomic"
	"time"

	"goBastion/internal/config"
)

type Watch struct {
	last    atomic.Int64
	stop    chan struct{}
	expired atomic.Bool
}

func Start(closeSession func()) *Watch {
	return StartWith(time.Duration(config.Get().Session.IdleTimeout), time.Duration(config.Get().Session.MaxSessionDuration), closeSession)
}
func StartWith(idle, max time.Duration, closeSession func()) *Watch {
	w := &Watch{stop: make(chan struct{})}
	w.Touch()
	start := time.Now()
	go func() {
		t := time.NewTicker(25 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-w.stop:
				return
			case now := <-t.C:
				if (idle > 0 && now.Sub(time.Unix(0, w.last.Load())) >= idle) || (max > 0 && now.Sub(start) >= max) {
					w.expired.Store(true)
					closeSession()
					return
				}
			}
		}
	}()
	return w
}
func (w *Watch) Touch()        { w.last.Store(time.Now().UnixNano()) }
func (w *Watch) Stop()         { close(w.stop) }
func (w *Watch) Expired() bool { return w.expired.Load() }

type Conn struct {
	net.Conn
	Watch *Watch
}

func (c *Conn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.Watch.Touch()
	}
	return n, e
}
func (c *Conn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	if n > 0 {
		c.Watch.Touch()
	}
	return n, e
}
