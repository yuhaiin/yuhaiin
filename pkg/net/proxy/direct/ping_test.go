package direct

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestMatchesEchoReply(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proto int
		reply icmp.Type
		ip    net.IP
	}{
		{name: "IPv4", proto: 1, reply: ipv4.ICMPTypeEchoReply, ip: net.IPv4(127, 0, 0, 1)},
		{name: "IPv6", proto: 58, reply: ipv6.ICMPTypeEchoReply, ip: net.ParseIP("::1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := []byte("sixteen-byte-key")
			packet, err := (&icmp.Message{
				Type: tc.reply,
				Body: &icmp.Echo{ID: 41, Seq: 123, Data: token},
			}).Marshal(nil)
			if err != nil {
				t.Fatal(err)
			}
			dest := &net.UDPAddr{IP: tc.ip}
			src := &net.UDPAddr{IP: tc.ip}
			if !matchesEchoReply(tc.proto, packet, src, dest, 123, token) {
				t.Fatal("valid echo reply not matched")
			}
			if matchesEchoReply(tc.proto, packet, src, dest, 124, token) {
				t.Fatal("wrong sequence matched")
			}
			if matchesEchoReply(tc.proto, packet, src, dest, 123, []byte("incorrect-token!")) {
				t.Fatal("wrong token matched")
			}
			if matchesEchoReply(tc.proto, packet, &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}, dest, 123, token) {
				t.Fatal("wrong source matched")
			}
			if matchesEchoReply(tc.proto, []byte{0, 1, 2}, src, dest, 123, token) {
				t.Fatal("truncated ICMP message matched")
			}
			if tc.proto == 1 {
				header := make([]byte, 20)
				header[0], header[9] = 0x45, 1
				if !matchesEchoReply(tc.proto, append(header, packet...), src, dest, 123, token) {
					t.Fatal("IPv4 reply with header not matched")
				}
			}
		})
	}
}

func TestMatchesEchoReplyZone(t *testing.T) {
	token := []byte("ipv6-zone-token!")
	packet, err := (&icmp.Message{
		Type: ipv6.ICMPTypeEchoReply,
		Body: &icmp.Echo{Seq: 22, Data: token},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Zone: "en0"}
	if !matchesEchoReply(58, packet, &net.UDPAddr{IP: dst.IP, Zone: "en0"}, dst, 22, token) {
		t.Fatal("link-local reply not matched")
	}
	if matchesEchoReply(58, packet, &net.UDPAddr{IP: dst.IP, Zone: "en1"}, dst, 22, token) {
		t.Fatal("wrong zone matched")
	}
}

func TestEchoOnce(t *testing.T) {
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	c := newFakeICMPConn(dst)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rtt, err := echoOnce(ctx, c, dst, 1, ipv4.ICMPTypeEcho)
	if err != nil {
		t.Fatal(err)
	}
	if rtt < 0 {
		t.Fatalf("negative RTT: %v", rtt)
	}
	if len(c.written) != 1 {
		t.Fatalf("sent %d requests, want one", len(c.written))
	}
}

func TestEchoOnceCancelled(t *testing.T) {
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	c := newFakeICMPConn(dst)
	c.noReply = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := echoOnce(ctx, c, dst, 1, ipv4.ICMPTypeEcho)
		done <- err
	}()
	select {
	case <-c.sent:
	case <-time.After(time.Second):
		t.Fatal("request not sent")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFrom did not unblock on cancellation")
	}
}

func TestApplyPingSocketOptions(t *testing.T) {
	called := false
	err := applyPingSocketOptions("udp4", 5, "", func(fd int32) bool {
		called = true
		return false
	})
	if !called {
		t.Fatal("mark/protect callback was not invoked")
	}
	if runtime.GOOS == "android" && err == nil {
		t.Fatal("Android protect failure must stop ping")
	}
	if runtime.GOOS != "android" && err != nil {
		t.Fatalf("unexpected platform mark failure: %v", err)
	}
}

type fakeICMPConn struct {
	target  *net.UDPAddr
	reply   chan []byte
	sent    chan struct{}
	closed  chan struct{}
	once    sync.Once
	written [][]byte
	noReply bool
}

func newFakeICMPConn(target *net.UDPAddr) *fakeICMPConn {
	return &fakeICMPConn{
		target: target,
		reply:  make(chan []byte, 1),
		sent:   make(chan struct{}),
		closed: make(chan struct{}),
	}
}

func (c *fakeICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case payload := <-c.reply:
		return copy(b, payload), c.target, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakeICMPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.written = append(c.written, bytes.Clone(p))
	c.once.Do(func() { close(c.sent) })
	if !c.noReply {
		m, err := icmp.ParseMessage(1, p)
		if err != nil {
			return 0, err
		}
		echo := m.Body.(*icmp.Echo)
		reply, err := (&icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: echo.Data},
		}).Marshal(nil)
		if err != nil {
			return 0, err
		}
		c.reply <- reply
	}
	return len(p), nil
}
func (c *fakeICMPConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *fakeICMPConn) LocalAddr() net.Addr              { return c.target }
func (c *fakeICMPConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeICMPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeICMPConn) SetWriteDeadline(time.Time) error { return nil }
