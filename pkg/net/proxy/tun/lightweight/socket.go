package lightweight

import (
	"net"
	"os"
	"time"
)

// Allocate a broadcast channel only while an operation actually waits. All
// condition checks, watch and notify calls hold the socket lock; notifications
// cannot be lost between checking a condition and registering its waiter.
func watch(ch *chan struct{}) <-chan struct{} {
	if *ch == nil {
		*ch = make(chan struct{})
	}
	return *ch
}
func notify(ch *chan struct{}) {
	if *ch != nil {
		close(*ch)
		*ch = nil
	}
}
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
