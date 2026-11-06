package sessionlimit

import (
	"testing"
	"time"
)

func TestLimits(t *testing.T) {
	for _, tc := range []struct {
		name      string
		idle, max time.Duration
		touch     bool
	}{{"idle", 60 * time.Millisecond, 0, false}, {"absolute", 0, 70 * time.Millisecond, true}} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			w := StartWith(tc.idle, tc.max, func() { close(done) })
			defer w.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			deadline := time.After(time.Second)
			for {
				select {
				case <-done:
					if !w.Expired() {
						t.Fatal("not marked expired")
					}
					return
				case <-tick.C:
					if tc.touch {
						w.Touch()
					}
				case <-deadline:
					t.Fatal("limit did not close session")
				}
			}
		})
	}
}
func TestDisabledLimit(t *testing.T) {
	w := StartWith(0, 0, func() { t.Error("disabled limit fired") })
	time.Sleep(80 * time.Millisecond)
	w.Stop()
}
