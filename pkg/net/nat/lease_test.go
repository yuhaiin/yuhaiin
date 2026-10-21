package nat

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type leaseTestProxy struct {
	netapi.Proxy
	mu       sync.Mutex
	acquired map[uint64]int
	active   map[uint64]int
	released chan uint64
}

func (p *leaseTestProxy) LeaseDestination(_ context.Context, addr netapi.Address) (func(), error) {
	ip, ok := addr.(netapi.IPAddress)
	if !ok || !netip.MustParsePrefix("198.18.0.0/15").Contains(ip.AddrPort().Addr()) {
		return nil, nil
	}
	key := addr.Comparable()
	p.mu.Lock()
	if p.acquired == nil {
		p.acquired = make(map[uint64]int)
		p.active = make(map[uint64]int)
	}
	p.acquired[key]++
	p.active[key]++
	p.mu.Unlock()
	return sync.OnceFunc(func() {
		p.mu.Lock()
		p.active[key]--
		p.mu.Unlock()
		if p.released != nil {
			p.released <- key
		}
	}), nil
}

func (p *leaseTestProxy) counts(addr netapi.Address) (acquired, active int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.acquired[addr.Comparable()], p.active[addr.Comparable()]
}

func TestNATFakeIPLeasesPreserveFullCone(t *testing.T) {
	listen := func() *net.UDPConn {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	first, second, third, outbound := listen(), listen(), listen(), listen()
	fake1, _ := netapi.ParseAddressPort("udp", "198.18.0.1", 443)
	fake2, _ := netapi.ParseAddressPort("udp", "198.18.0.2", 443)
	real1, real2 := unknownAddress(t, first.LocalAddr()), unknownAddress(t, second.LocalAddr())
	var dials atomic.Int32
	proxy := &leaseTestProxy{}
	proxy.Proxy = dispatchTestDialer{
		dial: func(context.Context) (net.PacketConn, error) {
			dials.Add(1)
			return nativeTestPacketConn{outbound}, nil
		},
		dispatch: func(_ context.Context, addr netapi.Address) (netapi.Address, error) {
			if _, active := proxy.counts(addr); active != 1 {
				t.Errorf("destination %s is not pinned during dispatch: %d", addr, active)
			}
			if addr.Comparable() == fake1.Comparable() {
				return real1, nil
			}
			return real2, nil
		},
	}
	table := NewTable(nil, proxy)
	t.Cleanup(func() { _ = table.Close() })
	src, _ := netapi.ParseAddressPort("udp", "192.0.2.1", 6000)
	replies := make(chan recordedPacket, 4)
	var peer net.Addr
	for _, target := range []struct {
		fake netapi.Address
		real *net.UDPConn
	}{{fake1, first}, {fake2, second}, {fake1, first}} {
		pkt := netapi.NewPacket(src, target.fake, pool.Clone([]byte("request")), netapi.WriteBackFunc(func(b []byte, addr net.Addr) (int, error) {
			replies <- recordedPacket{addr, append([]byte(nil), b...)}
			return len(b), nil
		}))
		err := table.Write(t.Context(), pkt)
		pkt.DecRef()
		if err != nil {
			t.Fatal(err)
		}
		_ = target.real.SetReadDeadline(time.Now().Add(time.Second))
		_, from, err := target.real.ReadFrom(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		if peer != nil && from.String() != peer.String() {
			t.Fatalf("destinations used different outbound sockets: %s and %s", peer, from)
		}
		peer = from
	}
	if dials.Load() != 1 {
		t.Fatalf("outbound socket count = %d", dials.Load())
	}
	for _, addr := range []netapi.Address{fake1, fake2} {
		if acquired, active := proxy.counts(addr); acquired != 1 || active != 1 {
			t.Fatalf("lease counts for %s = %d acquired, %d active", addr, acquired, active)
		}
	}
	if _, err := second.WriteTo([]byte("mapped"), peer); err != nil {
		t.Fatal(err)
	}
	if got := receiveRecorded(t, replies); got.destination.String() != fake2.String() {
		t.Fatalf("reply did not preserve synthetic identity: %s", got.destination)
	}
	if _, err := third.WriteTo([]byte("unsolicited"), peer); err != nil {
		t.Fatal(err)
	}
	if got := receiveRecorded(t, replies); got.destination.String() != third.LocalAddr().String() {
		t.Fatalf("unsolicited peer changed: %s", got.destination)
	}
	_ = table.Close()
	for _, addr := range []netapi.Address{fake1, fake2} {
		if _, active := proxy.counts(addr); active != 0 {
			t.Fatalf("lease for %s survived close", addr)
		}
	}
}

func TestNATFakeIPLeaseSurvivesMigration(t *testing.T) {
	local1, remote1 := net.Pipe()
	local2, remote2 := net.Pipe()
	first := &lifecyclePacketConn{Conn: local1, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	second := &lifecyclePacketConn{Conn: local2, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	calls := 0
	real, _ := netapi.ParseAddressPort("udp", "192.0.2.20", 443)
	proxy := &leaseTestProxy{Proxy: dispatchTestDialer{
		dial: func(ctx context.Context) (net.PacketConn, error) {
			netapi.GetContext(ctx).SetUDPMigrateID(1234)
			calls++
			if calls == 1 {
				return first, nil
			}
			return second, nil
		},
		dispatch: func(context.Context, netapi.Address) (netapi.Address, error) { return real, nil },
	}}
	source := NewSourceChan(nil, proxy)
	t.Cleanup(func() { _ = remote1.Close(); _ = remote2.Close(); _ = source.Close() })
	fake, _ := netapi.ParseAddressPort("udp", "198.18.0.1", 443)
	pkt := netapi.NewPacket(real, fake, []byte("request"), nil)
	defer pkt.DecRef()
	if err := source.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	_ = source.conn.Close()
	if _, active := proxy.counts(fake); active != 1 {
		t.Fatal("socket close released logical session's destination lease")
	}
	if err := source.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	if acquired, active := proxy.counts(fake); acquired != 1 || active != 1 {
		t.Fatalf("migration changed destination leases: acquired=%d active=%d", acquired, active)
	}
	_ = source.Close()
	if _, active := proxy.counts(fake); active != 0 {
		t.Fatal("lease survived source close")
	}
}

func TestNATFakeIPLeaseFailures(t *testing.T) {
	for _, failure := range []string{"dial", "dispatch", "send"} {
		t.Run(failure, func(t *testing.T) {
			local, remote := net.Pipe()
			base := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
			failed := errors.New("test failure")
			real, _ := netapi.ParseAddressPort("udp", "192.0.2.20", 443)
			proxy := &leaseTestProxy{Proxy: dispatchTestDialer{
				dial: func(context.Context) (net.PacketConn, error) {
					if failure == "dial" {
						return nil, failed
					}
					return failingTestPacketConn{lifecyclePacketConn: base, write: func(b []byte, _ net.Addr) (int, error) { return 0, failed }}, nil
				},
				dispatch: func(context.Context, netapi.Address) (netapi.Address, error) {
					if failure == "dispatch" {
						return nil, failed
					}
					return real, nil
				},
			}}
			source := NewSourceChan(nil, proxy)
			t.Cleanup(func() { _ = local.Close(); _ = remote.Close(); _ = source.Close() })
			fake, _ := netapi.ParseAddressPort("udp", "198.18.0.1", 443)
			pkt := netapi.NewPacket(real, fake, []byte("request"), nil)
			defer pkt.DecRef()
			if err := source.handleOne(pkt); !errors.Is(err, failed) {
				t.Fatalf("expected %s failure, got %v", failure, err)
			}
			wantActive := 0
			if failure == "send" {
				// The reverse mapping is published before sending, even on error.
				wantActive = 1
			}
			if acquired, active := proxy.counts(fake); acquired != 1 || active != wantActive {
				t.Fatalf("failure lease counts: acquired=%d active=%d, want active=%d", acquired, active, wantActive)
			}
			_ = source.Close()
			if _, active := proxy.counts(fake); active != 0 {
				t.Fatal("failure lease survived source close")
			}
		})
	}
}

func TestNATFakeIPLeaseBoundAllowsOrdinaryTargets(t *testing.T) {
	proxy := &leaseTestProxy{}
	source := &SourceControl{destinationLeaser: proxy}
	defer source.releaseDestinationLeases()
	for i := range maxCachedDestinations {
		addr, _ := netapi.ParseAddressPort("udp", "198.18.0.1", uint16(i+1))
		if err := source.acquireDestinationLease(t.Context(), addr); err != nil {
			t.Fatal(err)
		}
		source.retainDestinationLease(addr.Comparable())
	}
	overflow, _ := netapi.ParseAddressPort("udp", "198.18.0.2", 443)
	if err := source.acquireDestinationLease(t.Context(), overflow); !errors.Is(err, errReverseMappingFull) {
		t.Fatalf("overflow error = %v", err)
	}
	if acquired, active := proxy.counts(overflow); acquired != 1 || active != 0 {
		t.Fatalf("rejected lease leaked: acquired=%d active=%d", acquired, active)
	}
	ordinary, _ := netapi.ParseAddressPort("udp", "192.0.2.20", 443)
	if err := source.acquireDestinationLease(t.Context(), ordinary); err != nil {
		t.Fatalf("ordinary destination blocked by lease cap: %v", err)
	}
	if len(source.destinationLeases) != maxCachedDestinations {
		t.Fatalf("lease map grew beyond bound: %d", len(source.destinationLeases))
	}
}

func TestNATFailedResolutionReleasesFakeIPLease(t *testing.T) {
	local, remote := net.Pipe()
	base := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	domain, _ := netapi.ParseAddressPort("udp", "failed.example", 443)
	proxy := &leaseTestProxy{released: make(chan uint64, 2), Proxy: dispatchTestDialer{
		dial: func(ctx context.Context) (net.PacketConn, error) {
			netapi.GetContext(ctx).ConnOptions().Resolver().SetResolver(lookupResolver{lookup: func(context.Context, string) (*netapi.IPs, error) {
				return nil, errors.New("test lookup failure")
			}})
			return base, nil
		},
		dispatch: func(context.Context, netapi.Address) (netapi.Address, error) { return domain, nil },
	}}
	source := NewSourceChan(nil, proxy)
	t.Cleanup(func() { _ = remote.Close(); _ = source.Close() })
	fake, _ := netapi.ParseAddressPort("udp", "198.18.0.1", 443)
	for range 2 {
		enqueueResolutionPacket(t, source, fake, []byte("request"))
		select {
		case <-proxy.released:
		case <-time.After(time.Second):
			t.Fatal("failed resolution retained its destination lease")
		}
	}
	if acquired, active := proxy.counts(fake); acquired != 2 || active != 0 {
		t.Fatalf("failed resolution lease counts: acquired=%d active=%d", acquired, active)
	}
}
