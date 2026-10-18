package resolver

import (
	"context"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

type initialPacketProxy struct {
	netapi.Proxy
	conn *initialPacketConn
}

func (p initialPacketProxy) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return p.conn, nil
}

type initialPacketConn struct {
	closed chan struct{}
	writes chan int
	once   sync.Once
}

func (c *initialPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case c.writes <- len(b):
	default:
	}
	// IPv6 minimum link MTU minus the IPv6 and UDP headers.
	if len(b) > 1280-40-8 {
		return 0, syscall.EMSGSIZE
	}
	return len(b), nil
}
func (c *initialPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (c *initialPacketConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }
func (c *initialPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv6loopback, Port: 12345}
}
func (c *initialPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *initialPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *initialPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestDoQInitialFitsMinimumIPv6MTU(t *testing.T) {
	c := &initialPacketConn{closed: make(chan struct{}), writes: make(chan int, 16)}
	t.Cleanup(func() { _ = c.Close() })
	transport, err := NewDoQ(Config{Host: "[2001:db8::53]:853", Servername: "dns.example", Dialer: initialPacketProxy{direct.Default, c}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = transport.(*doq).initSession(ctx) }()
	select {
	case size := <-c.writes:
		if size < 1200 || size > 1280-40-8 {
			t.Errorf("QUIC Initial UDP payload %d cannot fit the minimum IPv6 MTU", size)
		}
	case <-time.After(time.Second):
		t.Error("DoQ did not send its Initial")
	}
	cancel()
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DoQ dial did not stop after cancellation")
	}
	_ = transport.Close()
}
