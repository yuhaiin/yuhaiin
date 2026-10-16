package lightweight

import (
	"net"
	"os"
	"time"
)

// changed channels implement broadcast wakeups. Replace/close only while the
// socket lock is held; waiters snapshot the channel and deadline under that lock.
func notify(ch *chan struct{}) { close(*ch); *ch = make(chan struct{}) }
func waitSocket(ch, done <-chan struct{}, deadline time.Time) error {
	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(d)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-done:
		return net.ErrClosed
	case <-ch:
		return nil
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}
