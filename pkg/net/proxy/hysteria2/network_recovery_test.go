package hysteria2

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

type networkHopProxy struct {
	netapi.Proxy
	manager *netstate.Manager
	opens   atomic.Int32
}

func (*networkHopProxy) Close() error { return nil }

type networkHopPacket struct {
	net.PacketConn
	path         netstate.Path
	registration *netstate.Registration
	invalid      atomic.Bool
	handler      atomic.Pointer[func()]
}

func (p *networkHopPacket) NetworkPath() netstate.Path { return p.path }
func (p *networkHopPacket) NetworkInvalidated() bool   { return p.invalid.Load() }
func (p *networkHopPacket) SetNetworkRecovery(handler func()) {
	p.handler.Store(new(handler))
	if p.invalid.Load() {
		handler()
	}
}
func (p *networkHopPacket) Close() error { _ = p.registration.Close(); return p.PacketConn.Close() }
func (p *networkHopProxy) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	raw, err := new(net.ListenConfig).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	c := &networkHopPacket{PacketConn: raw, path: p.manager.Capture("wifi", netip.Addr{}, 4)}
	c.registration = p.manager.Register(c.path, func(netstate.Event) {
		c.invalid.Store(true)
		if handler := c.handler.Load(); handler != nil {
			(*handler)()
		}
	})
	p.opens.Add(1)
	return c, nil
}

func TestNetworkRecoveryPreservesHoppingQUICAndActiveTCP(t *testing.T) {
	host, ca, _, _ := newTestServer(t, "")
	m := netstate.NewManager()
	network := netstate.Network{ID: "wifi", Index: 7, Name: "wifi", Available: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}
	snapshot := netstate.Snapshot{Networks: []netstate.Network{network}}
	m.Apply(snapshot, false)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	parent := &networkHopProxy{manager: m}
	proxy, err := NewClient(contractnode.Hysteria2{Host: host, HopAddresses: []string{host}, HopIntervalSeconds: 600, Auth: "secret", TLS: contractnode.TLS{CACert: [][]byte{ca}, ServerNames: []string{"test.example"}}}, parent)
	if err != nil {
		t.Fatal(err)
	}
	client := proxy.(*Client)
	defer client.Close()
	address, err := netapi.ParseAddress("tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.Conn(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	echo := func() {
		t.Helper()
		if _, err := stream.Write([]byte("echo")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != "echo" {
			t.Fatalf("live stream failed during recovery: %q %v", buf, err)
		}
	}
	echo()
	session := client.session
	for range 1000 {
		m.Apply(snapshot, true)
	}
	if parent.opens.Load() != 1 {
		t.Fatal("routine route events migrated an active QUIC transport")
	}
	m.AddressUnavailable(7, network.Addresses[0])
	network.Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.3")}
	snapshot.Networks = []netstate.Network{network}
	m.Apply(snapshot, false)
	for parent.opens.Load() < 2 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if parent.opens.Load() < 2 {
		t.Fatal("native socket migration was not triggered")
	}
	echo()
	if client.session != session || session.Context().Err() != nil {
		t.Fatal("network recovery replaced the QUIC session")
	}
}
