package tailscale

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

type malformedUnderlayProxy struct {
	netapi.Proxy
	conn      net.Conn
	err       error
	pc        net.PacketConn
	packetErr error
}

func (p *malformedUnderlayProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	return p.conn, p.err
}

func (p *malformedUnderlayProxy) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return p.pc, p.packetErr
}

func TestUnderlayNormalizesTypedNilTCP(t *testing.T) {
	var absent *net.TCPConn
	dialFailure := errors.New("refused")
	for _, tt := range []struct {
		name string
		conn net.Conn
		err  error
	}{
		{name: "failed dial typed nil", conn: absent, err: dialFailure},
		{name: "failed dial nil", err: dialFailure},
		{name: "broken success typed nil", conn: absent},
		{name: "broken success nil"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &malformedUnderlayProxy{Proxy: direct.Default, conn: tt.conn, err: tt.err}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			u := &underlay{owner: &Tailscale{dialer: p, ctx: ctx}}
			// Includes the exact DERP happy-eyeballs tcp4 path.
			for _, network := range []string{"tcp4", "tcp6", "tcp"} {
				address := "192.0.2.1:443"
				if network == "tcp6" {
					address = "[2001:db8::1]:443"
				}
				c, err := u.dialContext(ctx, network, address)
				if c != nil {
					t.Fatalf("%s: returned non-nil interface on failure: %T", network, c)
				}
				if err == nil {
					t.Fatalf("%s: missing connection accepted", network)
				}
				if tt.err != nil && !errors.Is(err, tt.err) {
					t.Fatalf("%s: error = %v, want %v", network, err, tt.err)
				}
			}
		})
	}
}

func TestUnderlayNormalizesTCPConnectionCleanup(t *testing.T) {
	one, two := net.Pipe()
	defer two.Close()
	fail := errors.New("partial dial failure")
	c, err := normalizeUnderlayConn(context.Background(), one, fail)
	if c != nil || !errors.Is(err, fail) {
		t.Fatalf("failed dial = (%v, %v)", c, err)
	}
	if _, err := one.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("failed dial leaked connection: %v", err)
	}

	one, two = net.Pipe()
	defer two.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, err = normalizeUnderlayConn(ctx, one, nil)
	if c != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial = (%v, %v)", c, err)
	}
	if _, err := one.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("canceled dial leaked connection: %v", err)
	}
}

func TestUnderlayNormalizesTypedNilUDP(t *testing.T) {
	var absent *net.UDPConn
	p, err := normalizeUnderlayPacketConn(context.Background(), absent, errors.New("bind failed"))
	if p != nil || err == nil {
		t.Fatalf("typed nil UDP error = (%v, %v)", p, err)
	}
	p, err = normalizeUnderlayPacketConn(context.Background(), absent, nil)
	if p != nil || err == nil {
		t.Fatalf("typed nil UDP success = (%v, %v)", p, err)
	}

	real, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, err = normalizeUnderlayPacketConn(ctx, real, nil)
	if p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled UDP bind = (%v, %v)", p, err)
	}
	if _, err := real.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:12345"))); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("canceled UDP bind leaked socket: %v", err)
	}
}
