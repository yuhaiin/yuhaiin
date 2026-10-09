package gvisor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"golang.org/x/net/nettest"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func tcpConnPair(t testing.TB) (net.Conn, *gonet.TCPConn) {
	t.Helper()
	return tcpConnPairWith(t, newTCPConn)
}

func tcpConnPairWith(t testing.TB, wrap func(*waiter.Queue, tcpip.Endpoint) net.Conn) (net.Conn, *gonet.TCPConn) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(func() { s.Close(); s.Wait() })
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatal(err)
	}
	addr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: 12345}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.Addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	wq := new(waiter.Queue)
	l, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	if err := l.Bind(addr); err != nil {
		t.Fatal(err)
	}
	if err := l.Listen(10); err != nil {
		t.Fatal(err)
	}
	entry, notify := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)
	peer, dialErr := gonet.DialTCP(s, addr, ipv4.ProtocolNumber)
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	t.Cleanup(func() { _ = peer.Close() })
	for {
		ep, queue, acceptErr := l.Accept(nil)
		if _, ok := acceptErr.(*tcpip.ErrWouldBlock); ok {
			select {
			case <-notify:
				continue
			case <-time.After(2 * time.Second):
				t.Fatal("accept timed out")
			}
		}
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		conn := wrap(queue, ep)
		t.Cleanup(func() { _ = conn.Close() })
		return conn, peer
	}
}

func TestTCPBufferedReadWaitsBeforeBorrowing(t *testing.T) {
	conn, peer := tcpConnPair(t)
	reader, ok := conn.(netapi.BufferReader)
	if !ok {
		t.Fatal("TUN TCP connection cannot defer borrowing its relay buffer")
	}
	var borrowed atomic.Int32
	done := make(chan error, 1)
	go func() {
		data, err := reader.ReadWithBuffer(func() []byte { borrowed.Add(1); return make([]byte, 32) })
		if err == nil && string(data) != "payload" {
			err = errors.New("corrupt payload")
		}
		done <- err
	}()
	// Let the real endpoint block, rather than testing only a fake reader.
	time.Sleep(20 * time.Millisecond)
	if borrowed.Load() != 0 {
		t.Fatal("idle TCP read borrowed a buffer")
	}
	if _, err := peer.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("read missed notification")
	}
	if borrowed.Load() != 1 {
		t.Fatalf("buffer acquired %d times", borrowed.Load())
	}
}

func TestTCPBufferedReadDeadlinesAndEOF(t *testing.T) {
	conn, peer := tcpConnPair(t)
	r := conn.(netapi.BufferReader)
	var borrowed int
	get := func() []byte { borrowed++; return make([]byte, 3) }
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if data, err := r.ReadWithBuffer(get); len(data) != 0 || !isTCPTimeout(err) {
		t.Fatalf("timeout: %q, %v", data, err)
	}
	if borrowed != 0 {
		t.Fatal("timeout borrowed buffer")
	}
	_ = conn.SetReadDeadline(time.Time{})
	if _, err := peer.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"abc", "def"} {
		data, err := r.ReadWithBuffer(get)
		if err != nil || string(data) != want {
			t.Fatalf("read: %q, %v, want %q", data, err, want)
		}
	}
	_ = peer.CloseWrite()
	if data, err := r.ReadWithBuffer(get); data != nil || err != io.EOF {
		t.Fatalf("EOF: %q %v", data, err)
	}
	if borrowed != 2 {
		t.Fatalf("borrowed %d times, including empty reads", borrowed)
	}
}

func isTCPTimeout(err error) bool {
	timeout, ok := errors.AsType[net.Error](err)
	return ok && timeout.Timeout()
}

func TestTCPBufferedReadOwnsReturnedDataAcrossClose(t *testing.T) {
	conn, peer := tcpConnPair(t)
	r := conn.(netapi.BufferReader)
	_, _ = peer.Write([]byte("keep"))
	buf := make([]byte, 16)
	data, err := r.ReadWithBuffer(func() []byte { return buf })
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !bytes.Equal(data, []byte("keep")) || &data[0] != &buf[0] {
		t.Fatal("returned buffer was replaced or invalidated")
	}
}

func TestTCPConnNetConn(t *testing.T) {
	nettest.TestConn(t, func() (net.Conn, net.Conn, func(), error) {
		conn, peer := tcpConnPair(t)
		return conn, peer, func() { _ = conn.Close(); _ = peer.Close() }, nil
	})
}

func TestTCPBufferedReadLargePayloadAndPanicRecovery(t *testing.T) {
	conn, peer := tcpConnPair(t)
	r := conn.(netapi.BufferReader)
	payload := bytes.Repeat([]byte("abcdefgh"), 32768)
	writeDone := make(chan error, 1)
	go func() { _, err := peer.Write(payload); _ = peer.CloseWrite(); writeDone <- err }()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("missing callback panic")
			}
		}()
		_, _ = r.ReadWithBuffer(func() []byte { panic("borrow failed") })
	}()
	// A failed callback must leave the endpoint and both read locks usable.
	first := make([]byte, 3)
	if _, err := io.ReadFull(conn, first); err != nil {
		t.Fatal(err)
	}
	got := bytes.Clone(first)
	for {
		calls := 0
		data, err := r.ReadWithBuffer(func() []byte { calls++; return make([]byte, 4096) })
		if calls > 1 {
			t.Fatal("multiple buffer leases in one read")
		}
		got = append(got, data...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("lost or corrupted data: got %d bytes, want %d", len(got), len(payload))
	}
}

func BenchmarkTCPRelay(b *testing.B) {
	for _, mode := range []string{"ordinary", "buffered"} {
		for _, size := range []int{64, 16384, 65536} {
			b.Run(fmt.Sprintf("%s/%d", mode, size), func(b *testing.B) {
				conn, peer := tcpRelayPair(b, mode)
				var reader io.Reader = conn
				done := make(chan error, 1)
				sink := &relayBenchmarkSink{size: size, ack: make(chan struct{})}
				go func() { _, err := relay.Copy(sink, reader); done <- err }()
				data := make([]byte, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := peer.Write(data); err != nil {
						b.Fatal(err)
					}
					<-sink.ack
				}
				_ = peer.CloseWrite()
				if err := <-done; err != nil {
					b.Fatal(err)
				}
			})
		}
	}
}

func tcpRelayPair(t testing.TB, mode string) (net.Conn, *gonet.TCPConn) {
	t.Helper()
	if mode == "ordinary" {
		return tcpConnPairWith(t, func(wq *waiter.Queue, ep tcpip.Endpoint) net.Conn { return gonet.NewTCPConn(wq, ep) })
	}
	return tcpConnPair(t)
}

type relayBenchmarkSink struct {
	size, received int
	ack            chan struct{}
}

func (s *relayBenchmarkSink) Write(b []byte) (int, error) {
	s.received += len(b)
	if s.received == s.size {
		s.received = 0
		s.ack <- struct{}{}
	}
	return len(b), nil
}

type idleRelayPool struct {
	pool.Pool
	live atomic.Int64
}

func (p *idleRelayPool) GetBytes(size int) []byte {
	b := p.Pool.GetBytes(size)
	p.live.Add(int64(len(b)))
	return b
}
func (p *idleRelayPool) PutBytes(b []byte) {
	p.live.Add(-int64(len(b)))
	p.Pool.PutBytes(b)
}

// Count actual checked-out relay storage, independently of heap sampling and
// background netstack allocations. Both cases exercise real idle TCP readers.
func TestIdleTCPRelayBuffers(t *testing.T) {
	const count = 32
	for _, mode := range []string{"ordinary", "buffered"} {
		t.Run(mode, func(t *testing.T) {
			conns := make([]net.Conn, count)
			for i := range conns {
				conns[i], _ = tcpRelayPair(t, mode)
			}
			tracker := &idleRelayPool{Pool: pool.DefaultPool}
			pool.DefaultPool = tracker
			defer func() { pool.DefaultPool = tracker.Pool }()
			done := make(chan error, count)
			for _, conn := range conns {
				var reader io.Reader = conn
				go func() { _, err := relay.Copy(io.Discard, reader); done <- err }()
			}
			time.Sleep(20 * time.Millisecond)
			live := tracker.live.Load()
			for _, conn := range conns {
				_ = conn.Close()
			}
			for range count {
				<-done
			}
			want := int64(0)
			if mode == "ordinary" {
				want = count * 16 * 1024
			}
			if live != want {
				t.Fatalf("idle relay buffers = %d bytes, want %d", live, want)
			}
			t.Logf("%d bytes / %d idle relays = %d B/relay", live, count, live/count)
		})
	}
}
