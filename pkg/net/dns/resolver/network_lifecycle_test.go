package resolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

type networkDNSProxy struct {
	netapi.Proxy
	manager *netstate.Manager
	iface   string
}

type networkDNSPacket struct {
	net.PacketConn
	manager      *netstate.Manager
	path         netstate.Path
	registration *netstate.Registration
}

func (p *networkDNSPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err != nil && !p.manager.Valid(p.path) {
		err = errors.Join(err, netstate.ErrInvalidated)
	}
	return n, addr, err
}
func (p *networkDNSPacket) Close() error { _ = p.registration.Close(); return p.PacketConn.Close() }

func (p networkDNSProxy) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	raw, err := new(net.ListenConfig).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	pc := &networkDNSPacket{PacketConn: raw, manager: p.manager, path: p.manager.Capture(p.iface, netip.Addr{}, 4)}
	pc.registration = p.manager.Register(pc.path, func(netstate.Event) { _ = raw.Close() })
	return pc, nil
}

type networkQueryLimiter struct {
	permits            chan struct{}
	acquired, released atomic.Int32
}

func (l *networkQueryLimiter) Acquire(ctx context.Context, _ int64) error {
	select {
	case l.permits <- struct{}{}:
		l.acquired.Add(1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (l *networkQueryLimiter) Release(int64) { l.released.Add(1); <-l.permits }

type pendingDNSPacket struct {
	msg  *dns.Msg
	from net.Addr
}

func TestNetworkChangeReleasesDNSAdmissionAndPreservesOtherNetworkAndCache(t *testing.T) {
	m := netstate.NewManager()
	a := netstate.Network{ID: "wifi", Index: 2, Name: "wifi", Available: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}
	b := netstate.Network{ID: "cell", Index: 3, Name: "cell", Available: true, Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.2")}}
	snapshot := netstate.Snapshot{Networks: []netstate.Network{a, b}}
	m.Apply(snapshot, false)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-workerDone })
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	packets := make(chan pendingDNSPacket, 16)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 8192)
		for {
			n, from, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := &dns.Msg{Data: append([]byte(nil), buf[:n]...)}
			if msg.Unpack() != nil {
				continue
			}
			select {
			case packets <- pendingDNSPacket{msg, from}:
			case <-ctx.Done():
				return
			}
		}
	}()
	t.Cleanup(func() { _ = server.Close(); <-serverDone })
	newClient := func(iface string) netapi.Resolver {
		transport, err := NewDoU(Config{Host: server.LocalAddr().String(), Dialer: networkDNSProxy{manager: m, iface: iface}})
		if err != nil {
			t.Fatal(err)
		}
		client := NewClient(Config{}, transport)
		t.Cleanup(func() { _ = client.Close() })
		return client
	}
	wifi, cell := newClient("wifi"), newClient("cell")
	limiter := &networkQueryLimiter{permits: make(chan struct{}, 1)}
	queryCtx := netapi.WithDNSQueryLimiter(ctx, limiter)
	question := func(name string) netapi.DNSQuestion {
		return netapi.DNSQuestion{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	}
	query := func(r netapi.Resolver, name string, ctx context.Context) <-chan error {
		result := make(chan error, 1)
		go func() { _, err := r.Raw(ctx, question(name)); result <- err }()
		return result
	}
	nextPacket := func() pendingDNSPacket {
		t.Helper()
		select {
		case p := <-packets:
			return p
		case <-ctx.Done():
			t.Fatal("DNS request did not reach local server")
			return pendingDNSPacket{}
		}
	}
	answer := func(p pendingDNSPacket) {
		t.Helper()
		q := p.msg.Question[0]
		msg := &dns.Msg{ID: p.msg.ID, Response: true, Question: p.msg.Question, Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: q.Header().Name, Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("203.0.113.5")}}}
		if err := msg.Pack(); err != nil {
			t.Fatal(err)
		}
		if _, err := server.WriteTo(msg.Data, p.from); err != nil {
			t.Fatal(err)
		}
	}
	finish := func(ch <-chan error, wantError bool) {
		t.Helper()
		select {
		case err := <-ch:
			if (err != nil) != wantError {
				t.Fatalf("DNS completion error=%v, wantError=%v", err, wantError)
			}
		case <-ctx.Done():
			t.Fatal("DNS request did not complete promptly")
		}
	}
	// Populate the real DNS cache before the transition.
	cached := query(wifi, "cached.example.", ctx)
	answer(nextPacket())
	finish(cached, false)
	affected := query(wifi, "blocked.example.", queryCtx)
	_ = nextPacket()
	unaffected := query(cell, "unaffected.example.", ctx)
	otherPacket := nextPacket()
	waiter := query(wifi, "replacement.example.", queryCtx)
	for range 100 {
		m.Apply(snapshot, true)
	}
	select {
	case err := <-affected:
		t.Fatalf("route-only update completed active query: %v", err)
	default:
	}
	// Queue cleanup of the old socket, then restore the same interface with
	// a new IP before cleanup runs. Only that old socket/query must fail.
	m.AddressUnavailable(2, a.Addresses[0])
	a.Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.3")}
	snapshot.Networks = []netstate.Network{a, b}
	m.Apply(snapshot, false)
	finish(affected, true)
	replacementPacket := nextPacket()
	answer(replacementPacket)
	finish(waiter, false)
	answer(otherPacket)
	finish(unaffected, false)
	if limiter.acquired.Load() != 2 || limiter.released.Load() != 2 || len(limiter.permits) != 0 {
		t.Fatalf("upstream permits leaked or double-released: acquired=%d released=%d", limiter.acquired.Load(), limiter.released.Load())
	}
	if _, err := netapi.CachedDNS(ctx, wifi, question("cached.example.")); err != nil {
		t.Fatalf("network change discarded valid DNS cache: %v", err)
	}
	// The same question as the old failed query can immediately succeed;
	// neither old singleflight completion nor failure state poisons recovery.
	retry := query(wifi, "blocked.example.", queryCtx)
	answer(nextPacket())
	finish(retry, false)
}
