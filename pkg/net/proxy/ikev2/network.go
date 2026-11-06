package ikev2

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

type udpSocketAffinity struct {
	conn *net.UDPConn
	path netstate.Path
}

// The IKE handshake owns temporary cancellation subscriptions. Once Connect
// has joined its setup goroutine, finish transfers ownership to the session.
// Later MOBIKE dials publish just one immutable socket/path pair, not a growing
// list of old sockets or per-socket watcher goroutines.
type udpDialLifecycle struct {
	manager *netstate.Manager
	pending atomic.Bool
	last    atomic.Pointer[udpSocketAffinity]
	setup   []*netstate.Registration
	once    sync.Once
	cancel  context.CancelCauseFunc
	dial    func(*net.UDPAddr) (*net.UDPConn, netstate.Path, error)
}

func (d *udpDialLifecycle) Dial(remote *net.UDPAddr) (*net.UDPConn, error) {
	raw, path, err := d.dial(remote)
	if err != nil {
		return nil, err
	}
	d.last.Store(&udpSocketAffinity{conn: raw, path: path})
	if d.pending.Load() {
		d.setup = append(d.setup, d.manager.Register(path, func(netstate.Event) {
			if d.pending.Load() {
				d.cancel(netstate.ErrInvalidated)
			}
		}))
	}
	return raw, nil
}

func (d *udpDialLifecycle) finish() error {
	d.once.Do(func() {
		d.pending.Store(false)
		for _, r := range d.setup {
			_ = r.Close()
		}
		d.setup = nil
	})
	if last := d.last.Load(); last != nil && !d.manager.Valid(last.path) {
		return netstate.ErrInvalidated
	}
	return nil
}

func (d *udpDialLifecycle) path(raw *net.UDPConn) netstate.Path {
	if last := d.last.Load(); last != nil && last.conn == raw {
		return last.path
	}
	return netstate.Path{}
}

type networkAffinity struct {
	conn    *net.UDPConn
	invalid atomic.Bool
}

func (s *session) startNetworkRecovery() {
	if s.conn.Load() == nil {
		return
	} // TCP is owned by the stream dialer.
	if s.ike.MobikeEnabled() {
		s.networkWake = make(chan *net.UDPConn, 1)
		s.networkDone = make(chan struct{})
	}
	s.roamMu.Lock()
	s.trackNetworkLocked()
	s.roamMu.Unlock()
	if s.networkWake != nil {
		go s.recoverNetwork(s.roamFrom)
	}
}

func (s *session) trackNetworkLocked() {
	_ = s.networkRegistration.Close()
	raw := s.conn.Load()
	if raw == nil || s.closing.Load() {
		return
	}
	local := raw.LocalAddr().(*net.UDPAddr).AddrPort().Addr().WithZone("").Unmap()
	path := netstate.Default.Capture("", local, 0)
	if s.socketAffinity != nil {
		path = s.socketAffinity(raw)
	}
	affinity := &networkAffinity{conn: raw}
	s.networkAffinity.Store(affinity)
	s.networkRegistration = netstate.Default.Register(path, func(netstate.Event) {
		affinity.invalid.Store(true)
		if s.networkWake == nil {
			_ = raw.Close()
			return
		}
		select {
		case s.networkWake <- raw:
		default:
		}
	})
}

func (s *session) recoverNetwork(roam func(*net.UDPConn) error) {
	defer close(s.networkDone)
	for {
		select {
		case <-s.stopKA:
			return
		case <-s.networkWake:
			affinity := s.networkAffinity.Load()
			if affinity == nil || !affinity.invalid.Load() {
				continue
			}
			old := affinity.conn
			for s.conn.Load() == old && !s.closing.Load() {
				netstate.RecoveryAttempts.Inc()
				if err := roam(old); err == nil {
					netstate.RecoverySuccesses.Inc()
					break
				} else {
					netstate.RecoveryFailures.Inc()
					s.logger.Warnf("ikev2: network recovery failed: %v", err)
				}
				timer := time.NewTimer(5 * time.Second)
				select {
				case <-s.stopKA:
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
	}
}
