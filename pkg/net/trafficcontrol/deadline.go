package trafficcontrol

import (
	"net"
	"sync"
	"time"
)

// Transport deadlines may change while a shaper is sleeping. The notification
// belongs to the connection direction, not to a packet or timer goroutine.
type streamDeadline struct {
	closed  bool
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func (d *streamDeadline) set(at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.at = at
	if d.changed != nil {
		close(d.changed)
		d.changed = make(chan struct{})
	}
}
func (d *streamDeadline) snapshot() (time.Time, <-chan struct{}, error) {
	if d == nil {
		return time.Time{}, nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changed == nil {
		d.changed = make(chan struct{})
	}
	if d.closed {
		return d.at, d.changed, net.ErrClosed
	}
	return d.at, d.changed, nil
}

func (d *streamDeadline) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	if d.changed != nil {
		close(d.changed)
	}
}
