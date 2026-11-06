package ikev2

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/ikev2/ike"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil/leaktest"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/vlog"
)

func TestIKEHandshakeCancellationAndOwnershipTransfer(t *testing.T) {
	for _, finishFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "established"}[finishFirst], func(t *testing.T) {
			m := netstate.NewManager()
			m.Apply(netstate.Snapshot{Networks: []netstate.Network{{ID: "wifi", Name: "wifi", Index: 2, Available: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}}}, false)
			path := m.Capture("wifi", netip.Addr{}, 4)
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(context.Canceled)
			raw := new(net.UDPConn)
			d := &udpDialLifecycle{manager: m, cancel: cancel, dial: func(*net.UDPAddr) (*net.UDPConn, netstate.Path, error) { return raw, path, nil }}
			d.pending.Store(true)
			if _, err := d.Dial(nil); err != nil {
				t.Fatal(err)
			}
			if finishFirst {
				if err := d.finish(); err != nil {
					t.Fatal(err)
				}
			}
			m.InterfaceUnavailable(2)
			workerCtx, stop := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { defer close(done); m.Run(workerCtx) }()
			defer func() { stop(); <-done; _ = d.finish() }()
			if finishFirst {
				if ctx.Err() != nil {
					t.Fatal("old setup subscription canceled established owner")
				}
			} else {
				select {
				case <-ctx.Done():
					if !errors.Is(context.Cause(ctx), netstate.ErrInvalidated) {
						t.Fatal(context.Cause(ctx))
					}
				case <-time.After(time.Second):
					t.Fatal("obsolete IKE handshake was not canceled")
				}
			}
			if err := d.finish(); !errors.Is(err, netstate.ErrInvalidated) {
				t.Fatal("stale completed handshake was accepted")
			}
			if d.path(raw) != path {
				t.Fatal("socket lifetime token was lost during owner transfer")
			}
		})
	}
}

func TestNetworkRecoveryNeverInvokesUnnegotiatedMOBIKE(t *testing.T) {
	leaktest.VerifyNoGoroutineLeaks(t)
	raw, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	s := &session{ike: ike.NewClient(ike.ClientConfig{}), stopKA: make(chan struct{}), logger: vlog.Discard()}
	s.conn.Store(raw)
	s.startNetworkRecovery()
	defer s.networkRegistration.Close()
	if s.networkDone != nil || s.networkWake != nil {
		t.Fatal("MOBIKE worker started without negotiated support")
	}
	if err := s.Roam(); err == nil {
		t.Fatal("unnegotiated MOBIKE was invoked")
	}
}

func TestIKERecoveryCoalescesInvalidationsAndStopsRetries(t *testing.T) {
	leaktest.VerifyNoGoroutineLeaks(t)
	old, fresh := new(net.UDPConn), new(net.UDPConn)
	s := &session{stopKA: make(chan struct{}), networkWake: make(chan *net.UDPConn, 1), networkDone: make(chan struct{}), logger: vlog.Discard()}
	s.conn.Store(old)
	initial := &networkAffinity{conn: old}
	initial.invalid.Store(true)
	s.networkAffinity.Store(initial)
	attempts := make(chan *net.UDPConn, 4)
	go s.recoverNetwork(func(expected *net.UDPConn) error {
		if expected == old {
			s.conn.Store(fresh)
			s.networkAffinity.Store(&networkAffinity{conn: fresh})
			attempts <- expected
			return nil
		}
		attempts <- expected
		return errors.New("network is not available yet")
	})
	defer func() {
		close(s.stopKA)
		select {
		case <-s.networkDone:
		case <-time.After(time.Second):
			t.Error("IKE recovery worker/timer leaked")
		}
	}()
	wait := func(want *net.UDPConn) {
		t.Helper()
		select {
		case actual := <-attempts:
			if actual != want {
				t.Fatal("stale socket selected for roam")
			}
		case <-time.After(time.Second):
			t.Fatal("recovery notification lost")
		}
	}
	s.networkWake <- old
	wait(old)
	// A delayed old notification may occupy the coalescing slot while the
	// current socket is also invalidated. Inspect current affinity, not payload.
	s.networkAffinity.Load().invalid.Store(true)
	s.networkWake <- old
	wait(fresh)
}
