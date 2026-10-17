package nat

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type staticResolver struct{ netapi.Resolver }

func (staticResolver) LookupIP(context.Context, string, ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return &netapi.IPs{A: []net.IP{net.IPv4(192, 0, 2, 20)}}, nil
}

type nativeTestPacketConn struct{ *net.UDPConn }

func (c nativeTestPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	addr, err := netapi.ParseSysAddr(a)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, net.UDPAddrFromAddrPort(addr.(netapi.IPAddress).AddrPort()))
}

type writeTestPacketConn struct {
	net.PacketConn
	write func([]byte, net.Addr) (int, error)
}

func (c writeTestPacketConn) WriteTo(b []byte, a net.Addr) (int, error) { return c.write(b, a) }
func (writeTestPacketConn) SetReadDeadline(time.Time) error             { return nil }

func TestNATRejectedSourceCanRecover(t *testing.T) {
	calls := make(chan struct{}, 2)
	local, remote := net.Pipe()
	conn := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	attempts := 0
	table := NewTable(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) {
		attempts++
		calls <- struct{}{}
		if attempts == 1 {
			return nil, &net.OpError{Op: "block", Err: errors.New("blocked target")}
		}
		return conn, nil
	}})
	t.Cleanup(func() { _ = remote.Close(); _ = table.Close() })
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	if err := table.Write(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("first dial missing")
	}
	allowed, _ := netapi.ParseAddressPort("udp", "192.0.2.99", 5353)
	next := netapi.NewPacket(pkt.Src(), allowed, pool.Clone([]byte("next")), netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { return len(b), nil }))
	defer next.DecRef()
	if err := table.Write(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, conn.writing)
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("allowed target did not get a dial")
	}
}

func TestNATFailedFirstSendKeepsReverseMapping(t *testing.T) {
	src, _ := netapi.ParseAddressPort("udp", "192.0.2.1", 6000)
	dst, _ := netapi.ParseAddressPort("udp", "example.test", 443)
	local, remote := net.Pipe()
	base := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	first, sent := make(chan struct{}), make(chan struct{})
	attempts := 0
	conn := failingTestPacketConn{lifecyclePacketConn: base, write: func(b []byte, _ net.Addr) (int, error) {
		attempts++
		if attempts == 1 {
			close(first)
			return 0, errors.New("temporary send failure")
		}
		close(sent)
		return len(b), nil
	}}
	source := NewSourceChan(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		netapi.GetContext(ctx).ConnOptions().Resolver().SetResolver(staticResolver{})
		return conn, nil
	}})
	t.Cleanup(func() { _ = remote.Close(); _ = source.Close() })
	replies := make(chan net.Addr, 1)
	enqueue := func() {
		pkt := netapi.NewPacket(src, dst, pool.Clone([]byte("test")), netapi.WriteBackFunc(func(b []byte, a net.Addr) (int, error) { replies <- a; return len(b), nil }))
		err := source.WritePacket(t.Context(), pkt)
		pkt.DecRef()
		if err != nil {
			t.Fatal(err)
		}
	}
	enqueue()
	awaitClosed(t, first)
	enqueue()
	awaitClosed(t, sent)
	if _, err := remote.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	select {
	case from := <-replies:
		if from.String() != dst.String() {
			t.Fatalf("reply from %s, want %s", from, dst)
		}
	case <-time.After(time.Second):
		t.Fatal("missing reply")
	}
}

type failingTestPacketConn struct {
	*lifecyclePacketConn
	write func([]byte, net.Addr) (int, error)
}

func (c failingTestPacketConn) WriteTo(b []byte, a net.Addr) (int, error) { return c.write(b, a) }
func (c failingTestPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 443}, err
}

func TestNATFirstReplyReverseMapping(t *testing.T) {
	original, _ := netapi.ParseAddressPort("udp", "198.18.0.1", 443)
	real := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 443}
	s := new(SourceControl)
	var got net.Addr
	c := writeTestPacketConn{write: func(b []byte, _ net.Addr) (int, error) {
		// Force the legal ordering: the receiver handles a reply before WriteTo returns.
		got = s.mapper.replyAddr(real)
		return len(b), nil
	}}
	if err := s.WriteTo([]byte("request"), real, original, c); err != nil {
		t.Fatal(err)
	}
	if got.String() != original.String() {
		t.Errorf("fast first reply address=%s, want %s", got, original)
	}
}

func TestNATCloseInterruptsBlockedReply(t *testing.T) {
	local, remote := net.Pipe()
	conn := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	source := NewSourceChan(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) { return conn, nil }})
	t.Cleanup(func() { _ = remote.Close(); _ = source.Close() })
	started := make(chan struct{})
	base := lifecyclePacket()
	pkt := netapi.NewPacket(base.Src(), base.Dst(), pool.Clone([]byte("test")), netapi.WriteBackContextFunc(func(ctx context.Context, _ []byte, _ net.Addr) (int, error) {
		close(started)
		<-ctx.Done()
		return 0, ctx.Err()
	}))
	base.DecRef()
	if err := source.WritePacket(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	pkt.DecRef()
	awaitClosed(t, conn.reading)
	if _, err := remote.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, started)
	done := make(chan struct{})
	go func() { _ = source.Close(); close(done) }()
	awaitClosed(t, done)
	if source.pending.Load() != 0 {
		t.Fatal("closed source retained packets")
	}
}

func TestNATLargeUDPReply(t *testing.T) {
	for _, size := range []int{1200, 4096, 60000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) { testNATUDPReply(t, size) })
	}
}
func testNATUDPReply(t *testing.T, size int) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	table := NewTable(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) { return nativeTestPacketConn{client}, nil }})
	defer table.Close()
	dst, err := netapi.ParseSysAddr(server.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	replies := make(chan []byte, 1)
	pkt := netapi.NewPacket(dst, dst, pool.Clone([]byte("request")), netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { replies <- bytes.Clone(b); return len(b), nil }))
	defer pkt.DecRef()
	if err := table.Write(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 16)
	_, from, err := server.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{'x'}, size)
	if _, err := server.WriteTo(payload, from); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-replies:
		if !bytes.Equal(got, payload) {
			t.Errorf("UDP datagram silently truncated: got=%d bytes, sent=%d", len(got), len(payload))
		}
	case <-time.After(time.Second):
		t.Fatal("reply not delivered")
	}
}

func TestNATDialingSourceIsNotIdle(t *testing.T) {
	dialing := make(chan struct{})
	s := NewSourceChan(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) { close(dialing); <-ctx.Done(); return nil, ctx.Err() }})
	defer s.Close()
	s.loopStopTime.Store(new(time.Now().Add(-2 * udpIdleTimeout())))
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	if err := s.WritePacket(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, dialing)
	if stopped, idle := s.IsIdle(); idle && time.Since(stopped) > udpIdleTimeout() {
		t.Error("actively dialing source is eligible for cleaner deletion")
	}
}

type dispatchTestDialer struct {
	lifecycleDialer
	dispatch func(context.Context, netapi.Address) (netapi.Address, error)
}

func (d dispatchTestDialer) Dispatch(ctx context.Context, a netapi.Address) (netapi.Address, error) {
	return d.dispatch(ctx, a)
}
func TestNATReconnectRefreshesDispatch(t *testing.T) {
	local1, remote1 := net.Pipe()
	local2, remote2 := net.Pipe()
	c1 := &lifecyclePacketConn{Conn: local1, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	c2 := &lifecyclePacketConn{Conn: local2, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	calls, dispatches := 0, 0
	oldAddr, _ := netapi.ParseAddressPort("udp", "192.0.2.10", 5353)
	newAddr, _ := netapi.ParseAddressPort("udp", "192.0.2.11", 5353)
	s := NewSourceChan(nil, dispatchTestDialer{dial: func(context.Context) (net.PacketConn, error) {
		calls++
		if calls == 1 {
			return c1, nil
		}
		return c2, nil
	}, dispatch: func(context.Context, netapi.Address) (netapi.Address, error) {
		dispatches++
		if calls == 1 {
			return oldAddr, nil
		}
		return newAddr, nil
	}})
	defer func() { _ = remote1.Close(); _ = remote2.Close(); _ = s.Close() }()
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	// Direct handleOne calls serialize the same way as run, without queue timing.
	if err := s.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	_ = s.conn.Close()
	if err := s.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	got := s.mapper.targets[pkt.Dst().Comparable()]
	if got.String() != newAddr.String() {
		t.Errorf("reconnected flow still uses %s, want %s; dials=%d dispatches=%d", got, newAddr, calls, dispatches)
	}
}

func TestNATMigratingReconnectKeepsPinnedTarget(t *testing.T) {
	local1, remote1 := net.Pipe()
	local2, remote2 := net.Pipe()
	c1 := &lifecyclePacketConn{Conn: local1, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	c2 := &lifecyclePacketConn{Conn: local2, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	calls, dispatches := 0, 0
	oldAddr, _ := netapi.ParseAddressPort("udp", "192.0.2.10", 5353)
	newAddr, _ := netapi.ParseAddressPort("udp", "192.0.2.11", 5353)
	s := NewSourceChan(nil, dispatchTestDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		netapi.GetContext(ctx).SetUDPMigrateID(9922)
		calls++
		if calls == 1 {
			return c1, nil
		}
		return c2, nil
	}, dispatch: func(context.Context, netapi.Address) (netapi.Address, error) {
		dispatches++
		if calls == 1 {
			return oldAddr, nil
		}
		return newAddr, nil
	}})
	defer func() { _ = remote1.Close(); _ = remote2.Close(); _ = s.Close() }()
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	// Direct handleOne calls serialize the same way as run, without queue timing.
	if err := s.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	_ = s.conn.Close()
	if err := s.handleOne(pkt); err != nil {
		t.Fatal(err)
	}
	got := s.mapper.targets[pkt.Dst().Comparable()]
	if got.String() != oldAddr.String() {
		t.Errorf("reconnected flow still uses %s, want %s; dials=%d dispatches=%d", got, oldAddr, calls, dispatches)
	}
}

func TestNATFullConePreserved(t *testing.T) {
	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	first, second, third, outbound := listen(), listen(), listen(), listen()
	var dials atomic.Int32
	table := NewTable(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) {
		dials.Add(1)
		return nativeTestPacketConn{outbound}, nil
	}})
	defer table.Close()
	src, _ := netapi.ParseAddressPort("udp", "192.0.2.1", 6000)
	received := make(chan net.Addr, 1)
	for _, target := range []*net.UDPConn{first, second} {
		dst, err := netapi.ParseSysAddr(target.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		pkt := netapi.NewPacket(src, dst, pool.Clone([]byte("test")), netapi.WriteBackFunc(func(b []byte, a net.Addr) (int, error) { received <- a; return len(b), nil }))
		err = table.Write(t.Context(), pkt)
		pkt.DecRef()
		if err != nil {
			t.Fatal(err)
		}
	}
	var peers []net.Addr
	for _, server := range []*net.UDPConn{first, second} {
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		_, from, err := server.ReadFrom(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		peers = append(peers, from)
	}
	if dials.Load() != 1 || peers[0].String() != peers[1].String() {
		t.Fatalf("full-cone mapping split: dials=%d peers=%v", dials.Load(), peers)
	}
	if _, err := third.WriteTo([]byte("unsolicited"), peers[0]); err != nil {
		t.Fatal(err)
	}
	select {
	case from := <-received:
		if from.String() != third.LocalAddr().String() {
			t.Fatalf("unexpected reply from %s", from)
		}
	case <-time.After(time.Second):
		t.Fatal("unsolicited third-party reply was filtered")
	}
}

type blockingResolver struct {
	netapi.Resolver
	started chan struct{}
	release chan struct{}
}

func (r blockingResolver) LookupIP(ctx context.Context, _ string, _ ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	close(r.started)
	select {
	case <-r.release:
		return &netapi.IPs{A: []net.IP{net.IPv4(192, 0, 2, 20)}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type addressRecordingConn struct {
	*lifecyclePacketConn
	writes chan net.Addr
}

func (c addressRecordingConn) WriteTo(b []byte, a net.Addr) (int, error) {
	c.writes <- a
	return len(b), nil
}
func TestNATSlowDNSDoesNotBlockOtherDestination(t *testing.T) {
	local, remote := net.Pipe()
	conn := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	started, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	writes := make(chan net.Addr, 2)
	source := NewSourceChan(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		netapi.GetContext(ctx).ConnOptions().Resolver().SetResolver(blockingResolver{started: started, release: release})
		return addressRecordingConn{conn, writes}, nil
	}})
	t.Cleanup(func() { releaseOnce(); _ = remote.Close(); _ = source.Close() })
	src, _ := netapi.ParseAddressPort("udp", "192.0.2.1", 6000)
	slow, _ := netapi.ParseAddressPort("udp", "slow.test", 443)
	fast, _ := netapi.ParseAddressPort("udp", "192.0.2.99", 443)
	enqueue := func(dst netapi.Address) {
		pkt := netapi.NewPacket(src, dst, pool.Clone([]byte("test")), netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { return len(b), nil }))
		err := source.WritePacket(t.Context(), pkt)
		pkt.DecRef()
		if err != nil {
			t.Fatal(err)
		}
	}
	enqueue(slow)
	awaitClosed(t, started)
	enqueue(fast)
	select {
	case got := <-writes:
		if got.String() != fast.String() {
			t.Fatalf("got %s before DNS completed, want %s", got, fast)
		}
	case <-time.After(time.Second):
		t.Fatal("ready IP blocked behind DNS")
	}
	releaseOnce()
	for range 1 {
		select {
		case <-writes:
		case <-time.After(time.Second):
			t.Fatal("queued packet did not send after DNS completed")
		}
	}
}
