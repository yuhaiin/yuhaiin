package nat

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

type networkPacketConn struct {
	net.PacketConn
	registration *netstate.Registration
}

func (c *networkPacketConn) Close() error { _ = c.registration.Close(); return c.PacketConn.Close() }

func TestNetworkInvalidationReplacesOnlyAffectedFullConeSocket(t *testing.T) {
	m := netstate.NewManager()
	a := netstate.Network{ID: "wifi", Index: 2, Name: "wifi", Available: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}
	b := netstate.Network{ID: "cell", Index: 3, Name: "cell", Available: true, Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.2")}}
	snapshot := netstate.Snapshot{Networks: []netstate.Network{a, b}}
	m.Apply(snapshot, false)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	counts := make(map[string]int)
	newSource := func(iface string) *SourceControl {
		s := NewSourceChan(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) {
			counts[iface]++
			local, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			raw := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
			pc := &networkPacketConn{PacketConn: raw}
			pc.registration = m.Register(m.Capture(iface, netip.Addr{}, 4), func(netstate.Event) { _ = raw.Close() })
			return pc, nil
		}})
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	wifi, cell := newSource("wifi"), newSource("cell")
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	if err := wifi.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	if err := cell.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	old, unaffected := wifi.conn, cell.conn
	for range 1000 {
		m.Apply(snapshot, true)
	}
	if old.closed.Load() || unaffected.closed.Load() {
		t.Fatal("routing-table activity disrupted full-cone mappings")
	}
	m.AddressUnavailable(2, a.Addresses[0])
	a.Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.3")}
	snapshot.Networks = []netstate.Network{a, b}
	m.Apply(snapshot, false)
	deadline := time.Now().Add(time.Second)
	for !old.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !old.closed.Load() {
		t.Fatal("obsolete underlying UDP reader did not retire")
	}
	if err := wifi.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	if err := cell.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	if counts["wifi"] != 2 || counts["cell"] != 1 || wifi.conn == old || cell.conn != unaffected || unaffected.closed.Load() {
		t.Fatalf("NAT recovery affected the wrong source/network: dials=%v", counts)
	}
}
