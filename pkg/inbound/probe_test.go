package inbound

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

type probeTestProxy struct {
	netapi.Proxy
	tcp, udp atomic.Int32
	conn     net.Conn
	packet   net.PacketConn
}

func (p *probeTestProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	p.tcp.Add(1)
	return p.conn, nil
}
func (p *probeTestProxy) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	p.udp.Add(1)
	return p.packet, nil
}
func (*probeTestProxy) Close() error { return nil }

type probeTestPacket struct {
	net.PacketConn
	writes atomic.Int32
	closed atomic.Int32
}

func (p *probeTestPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.writes.Add(1)
	return len(b), nil
}
func (*probeTestPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	return copy(b, "reply"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}, nil
}
func (p *probeTestPacket) Close() error { p.closed.Add(1); return nil }
func testProbePreparer(ctx context.Context, a netapi.Address) (netapi.Address, error) {
	netapi.GetContext(ctx).SetMatchedRule("probe-rule", "Probe policy")
	return a, nil
}

func TestProbeSharesDatagramPoliciesAndPinsSingleSocket(t *testing.T) {
	l := NewInbound(netapi.NewErrProxy(errors.New("routing must not select an outbound")))
	defer l.Close()
	cfg := trafficcontrol.Config{Enabled: true, Profiles: map[string]trafficcontrol.Profile{"probe": {Upload: trafficcontrol.Rate{BytesPerSecond: 1, BurstBytes: 4}}}, RouteProfiles: map[string]string{"probe-rule": "probe"}}
	if err := l.SetTrafficControl(cfg); err != nil {
		t.Fatal(err)
	}
	raw := new(probeTestPacket)
	fixed := &probeTestProxy{packet: raw}
	p := l.ProbeProxy(t.Context(), fixed, testProbePreparer)
	a, _ := netapi.ParseAddress("udp", "192.0.2.1:53")
	c, err := p.PacketConn(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.WriteTo([]byte("1234"), a); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo([]byte("5"), a); !errors.Is(err, trafficcontrol.ErrLocalLimit) {
		t.Fatal("route cap bypassed", err)
	}
	// Applying a live change affects the existing session; its outbound stays pinned.
	cfg.Profiles["probe"] = trafficcontrol.Profile{}
	if err := l.SetTrafficControl(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo([]byte("after change"), a); err != nil {
		t.Fatal(err)
	}
	if fixed.udp.Load() != 1 || raw.writes.Load() != 2 {
		t.Fatal("session was replaced or a rejected packet sent")
	}
	usage := l.TrafficControlStatus().Shaping
	if usage.RejectedUploadDatagrams != 1 {
		t.Fatal(usage)
	}
}

func TestProbeRoutingDenialAndSTUNAlternateTargets(t *testing.T) {
	l := NewInbound(netapi.NewErrProxy(errors.New("unexpected default route")))
	defer l.Close()
	raw := new(probeTestPacket)
	fixed := &probeTestProxy{packet: raw}
	p := l.ProbeProxy(t.Context(), fixed, func(ctx context.Context, a netapi.Address) (netapi.Address, error) {
		if a.Port() == 9 {
			return nil, &net.OpError{Op: "block", Err: errors.New("policy denied")}
		}
		return testProbePreparer(ctx, a)
	})
	blocked, _ := netapi.ParseAddress("udp", "192.0.2.1:9")
	if _, err := p.PacketConn(t.Context(), blocked); !netapi.IsBlockError(err) {
		t.Fatal(err)
	}
	if fixed.udp.Load() != 0 {
		t.Fatal("blocked target created a channel")
	}
	first, _ := netapi.ParseAddress("udp", "192.0.2.1:53")
	c, err := p.PacketConn(t.Context(), first)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.WriteTo([]byte("blocked alternate"), blocked); !netapi.IsBlockError(err) {
		t.Fatal(err)
	}
	for i := range 7 {
		a, _ := netapi.ParseAddress("udp", net.JoinHostPort("192.0.2.1", strconv.Itoa(100+i)))
		if _, err := c.WriteTo([]byte("STUN"), a); err != nil {
			t.Fatal(err)
		}
	}
	extra, _ := netapi.ParseAddress("udp", "192.0.2.1:108")
	if _, err := c.WriteTo([]byte("extra"), extra); !errors.Is(err, trafficcontrol.ErrLocalLimit) {
		t.Fatal("unbounded destination cache", err)
	}
	if fixed.udp.Load() != 1 || raw.writes.Load() != 7 {
		t.Fatal("alternate endpoint bypassed policy or split socket")
	}
}

func TestProbeCancellationReleasesStreamAndDatagramLeases(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := NewInbound(netapi.NewErrProxy(errors.New("unused")))
		defer l.Close()
		client, peer := net.Pipe()
		defer peer.Close()
		packet := new(probeTestPacket)
		fixed := &probeTestProxy{conn: client, packet: packet}
		ctx, cancel := context.WithCancel(t.Context())
		p := l.ProbeProxy(ctx, fixed, testProbePreparer)
		a, _ := netapi.ParseAddress("tcp", "192.0.2.1:443")
		c, err := p.Conn(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		pc, err := p.PacketConn(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		if l.TrafficControlStatus().Global.Sessions != 2 {
			t.Fatal("probe did not share root governor")
		}
		cancel()
		synctest.Wait()
		if l.TrafficControlStatus().Global.Sessions != 0 || packet.closed.Load() != 1 {
			t.Fatal("cancelled probe leaked leases or socket")
		}
		if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		_ = c.Close()
		_ = pc.Close()
		if packet.closed.Load() != 1 {
			t.Fatal("packet channel closed twice")
		}
	})
}

func TestClosedControllerCannotStartNewProbeChannels(t *testing.T) {
	l := NewInbound(netapi.NewErrProxy(errors.New("unused")))
	if err := l.SetTrafficControl(trafficcontrol.Config{}); err != nil {
		t.Fatal(err)
	}
	raw := &probeTestProxy{packet: new(probeTestPacket)}
	p := l.ProbeProxy(t.Context(), raw, testProbePreparer)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if l.ProbePolicyReady() {
		t.Fatal("closed inbound still ready")
	}
	a, _ := netapi.ParseAddress("udp", "192.0.2.1:53")
	if _, err := p.PacketConn(t.Context(), a); !errors.Is(err, trafficcontrol.ErrLocalLimit) {
		t.Fatal(err)
	}
	if _, err := p.Conn(t.Context(), a); !errors.Is(err, trafficcontrol.ErrLocalLimit) {
		t.Fatal(err)
	}
	if raw.udp.Load() != 0 || raw.tcp.Load() != 0 {
		t.Fatal("shutdown admitted a network channel")
	}
}
