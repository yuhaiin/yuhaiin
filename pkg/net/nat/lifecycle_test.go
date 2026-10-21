package nat

import (
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

func awaitClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("worker did not exit")
	}
}

func TestTableCloseStopsCleaner(t *testing.T) {
	table := NewTable(nil, nil)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { _ = table.Close() })
	}
	wg.Wait()
	awaitClosed(t, table.done)
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	if err := table.Write(t.Context(), pkt); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestTableCleanerSleepsWhenEmptyAndRestarts(t *testing.T) {
	table := &Table{stop: make(chan struct{}), done: make(chan struct{}), cleanerWake: make(chan struct{}, 1)}
	var checks atomic.Int32
	go table.runCleaner(func() time.Duration { checks.Add(1); return 10 * time.Millisecond })
	defer table.Close()
	time.Sleep(30 * time.Millisecond)
	if checks.Load() != 0 {
		t.Fatal("empty NAT table started a timer")
	}
	for key := uint64(1); key <= 2; key++ {
		source := NewSourceChan(nil, nil)
		old := time.Now().Add(-time.Second)
		source.loopStopTime.Store(&old)
		table.sourceControl.Store(key, source)
		table.cleanerWake <- struct{}{}
		awaitClosed(t, source.done)
		if _, exists := table.sourceControl.Load(key); exists {
			t.Fatal("idle source not removed")
		}
		time.Sleep(20 * time.Millisecond)
		before := checks.Load()
		time.Sleep(30 * time.Millisecond)
		if checks.Load() != before {
			t.Fatal("cleaner continued waking after becoming empty")
		}
	}
}

type lifecyclePacketConn struct {
	net.Conn
	reading                        chan struct{}
	writing                        chan struct{}
	closed                         chan struct{}
	readOnce, writeOnce, closeOnce sync.Once
	blockWrite                     bool
}

func (c *lifecyclePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readOnce.Do(func() { close(c.reading) })
	n, err := c.Read(b)
	return n, netapi.EmptyAddr, err
}
func (c *lifecyclePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.writeOnce.Do(func() { close(c.writing) })
	if c.blockWrite {
		return c.Write(b)
	}
	return len(b), nil
}
func (c *lifecyclePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type lifecycleDialer struct {
	netapi.Proxy
	dial func(context.Context) (net.PacketConn, error)
}

func (d lifecycleDialer) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	return d.dial(ctx)
}
func (d lifecycleDialer) Dispatch(_ context.Context, addr netapi.Address) (netapi.Address, error) {
	return addr, nil
}
func lifecyclePacket() *netapi.Packet {
	addr, _ := netapi.ParseAddressPort("udp", "192.0.2.1", 5353)
	b := pool.GetBytes(4)
	copy(b, "test")
	return netapi.NewPacket(addr, addr, b, netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { return len(b), nil }))
}

func TestSourceCloseInterruptsIO(t *testing.T) {
	for _, blockWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "Read", true: "Write"}[blockWrite], func(t *testing.T) {
			local, remote := net.Pipe()
			packet := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{}), blockWrite: blockWrite}
			u := NewSourceChan(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) { return packet, nil }})
			t.Cleanup(func() { _ = remote.Close(); _ = u.Close() })
			pkt := lifecyclePacket()
			if err := u.WritePacket(t.Context(), pkt); err != nil {
				t.Fatal(err)
			}
			pkt.DecRef()
			awaitClosed(t, packet.reading)
			awaitClosed(t, packet.writing)
			done := make(chan struct{})
			go func() { _ = u.Close(); close(done) }()
			awaitClosed(t, done)
			awaitClosed(t, packet.closed)
			if _, idle := u.IsIdle(); !idle {
				t.Fatal("closed reader still active")
			}
			if pkt.GetPayload() != nil {
				t.Fatal("retained processed packet")
			}
		})
	}
}

func TestSourceCloseCancelsDialAndDrainsQueue(t *testing.T) {
	dialing := make(chan struct{})
	u := NewSourceChan(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) { close(dialing); <-ctx.Done(); return nil, ctx.Err() }})
	t.Cleanup(func() { _ = u.Close() })
	var packets []*netapi.Packet
	for range 4 {
		pkt := lifecyclePacket()
		if err := u.WritePacket(t.Context(), pkt); err != nil {
			t.Fatal(err)
		}
		pkt.DecRef()
		packets = append(packets, pkt)
	}
	awaitClosed(t, dialing)
	_ = u.Close()
	for _, pkt := range packets {
		if pkt.GetPayload() != nil {
			t.Fatal("retained queued packet")
		}
	}
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	if err := u.WritePacket(t.Context(), pkt); !errors.Is(err, context.Canceled) {
		t.Fatalf("enqueue after close: %v", err)
	}
}

func TestFailedSourceDialIsIdle(t *testing.T) {
	failed := make(chan struct{})
	u := NewSourceChan(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) { close(failed); return nil, net.ErrClosed }})
	defer u.Close()
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	if err := u.WritePacket(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, failed)
	// The dial callback signals before it returns; idle means the sender has
	// also finished processing and released its in-flight admission.
	deadline := time.Now().Add(time.Second)
	for u.pending.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, idle := u.IsIdle(); !idle {
		t.Fatal("failed first dial cannot be reaped")
	}
}

func TestTableConcurrentWriteAndClose(t *testing.T) {
	dialer := lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) { <-ctx.Done(); return nil, ctx.Err() }}
	table := NewTable(nil, dialer)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			for range 16 {
				pkt := lifecyclePacket()
				_ = table.Write(t.Context(), pkt)
				pkt.DecRef()
			}
		})
	}
	wg.Go(func() { <-start; _ = table.Close() })
	close(start)
	wg.Wait()
	table.sourceControl.Range(func(_ uint64, _ *SourceControl) bool { t.Error("closed table retains source controls"); return false })
}

func TestOldReaderExitDoesNotMarkReplacementIdle(t *testing.T) {
	local1, remote1 := net.Pipe()
	local2, remote2 := net.Pipe()
	first := &lifecyclePacketConn{Conn: local1, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	second := &lifecyclePacketConn{Conn: local2, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	calls := 0
	u := NewSourceChan(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return second, nil
	}})
	blocked, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		_ = remote1.Close()
		_ = remote2.Close()
		_ = u.Close()
	})
	base := lifecyclePacket()
	pkt := netapi.NewPacket(base.Src(), base.Dst(), pool.Clone(base.GetPayload()), netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { close(blocked); <-release; return len(b), nil }))
	base.DecRef()
	if err := u.WritePacket(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	pkt.DecRef()
	awaitClosed(t, first.reading)
	if _, err := remote1.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, blocked)
	// First receive loop exits, but its writeback worker is still unwinding.
	_ = remote1.Close()
	awaitClosed(t, first.closed)
	next := lifecyclePacket()
	if err := u.WritePacket(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	next.DecRef()
	awaitClosed(t, second.reading)
	releaseOnce.Do(func() { close(release) })
	deadline := time.Now().Add(time.Second)
	for u.readers.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if u.readers.Load() != 1 {
		t.Fatal("old reader did not finish")
	}
	if _, idle := u.IsIdle(); idle {
		t.Fatal("old reader marked an active replacement idle")
	}
}

func TestSourceReconnectPreservesControlAndMigrateID(t *testing.T) {
	local1, remote1 := net.Pipe()
	local2, remote2 := net.Pipe()
	first := &lifecyclePacketConn{Conn: local1, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	second := &lifecyclePacketConn{Conn: local2, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	ids := make(chan uint64, 2)
	calls := 0
	table := NewTable(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		store := netapi.GetContext(ctx)
		ids <- store.GetUDPMigrateID()
		store.SetUDPMigrateID(9981)
		calls++
		if calls == 1 {
			return first, nil
		}
		return second, nil
	}})
	t.Cleanup(func() { _ = remote1.Close(); _ = remote2.Close(); _ = table.Close() })
	const migrationKey = 12345
	write := func() {
		pkt := lifecyclePacket()
		pkt.MigrateID = migrationKey
		if err := table.Write(t.Context(), pkt); err != nil {
			t.Fatal(err)
		}
		pkt.DecRef()
	}
	write()
	awaitClosed(t, first.reading)
	awaitClosed(t, first.writing)
	before, ok := table.sourceControl.Load(migrationKey)
	if !ok {
		t.Fatal("missing source control")
	}
	_ = remote1.Close()
	awaitClosed(t, first.closed)
	deadline := time.Now().Add(time.Second)
	for {
		_, idle := before.IsIdle()
		if idle {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reader did not stop")
		}
		time.Sleep(time.Millisecond)
	}
	if err := before.ctx.Err(); err != nil {
		t.Fatalf("connection close destroyed reusable control: %v", err)
	}
	write()
	awaitClosed(t, second.reading)
	awaitClosed(t, second.writing)
	after, ok := table.sourceControl.Load(migrationKey)
	if !ok || after != before {
		t.Fatal("connection close replaced SourceControl")
	}
	if id := <-ids; id != 0 {
		t.Fatalf("initial migrate ID=%d", id)
	}
	if id := <-ids; id != 9981 {
		t.Fatalf("reconnect lost migrate ID: %d", id)
	}
}

func TestMigrationDuringWriteBackDoesNotCloseUDPSession(t *testing.T) {
	local, remote := net.Pipe()
	conn := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	table := NewTable(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) { return conn, nil }})
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); _ = remote.Close(); _ = table.Close() })
	firstSrc := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	secondSrc := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
	dst, _ := netapi.ParseAddressPort("udp", "192.0.2.1", 5353)
	const key = 4321
	write := func(src net.Addr, cb netapi.WriteBackFunc) {
		pkt := netapi.NewPacket(src, dst, pool.Clone([]byte("request")), cb, netapi.WithMigrateID(key))
		if err := table.Write(t.Context(), pkt); err != nil {
			t.Fatal(err)
		}
		pkt.DecRef()
	}
	write(firstSrc, func([]byte, net.Addr) (int, error) { close(started); <-release; return 0, net.ErrClosed })
	awaitClosed(t, conn.reading)
	awaitClosed(t, conn.writing)
	if _, err := remote.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, started)
	delivered := make(chan string, 1)
	write(secondSrc, func(b []byte, _ net.Addr) (int, error) { delivered <- string(b); return len(b), nil })
	source, _ := table.sourceControl.Load(key)
	// Wait for run to install the new transport before failing the old callback.
	deadline := time.Now().Add(time.Second)
	for source.reply.Load().source != secondSrc && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if source.reply.Load().source != secondSrc {
		t.Fatal("migration did not retarget replies")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case data := <-delivered:
		if data != "reply" {
			t.Fatalf("retry reply=%q", data)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight reply was lost on migration")
	}
	select {
	case <-conn.closed:
		t.Fatal("obsolete callback closed the reused UDP session")
	default:
	}
	if _, idle := source.IsIdle(); idle {
		t.Fatal("migrated session became idle")
	}
}

func TestRetiredSourceIsReplacedOnAdmission(t *testing.T) {
	local, remote := net.Pipe()
	conn := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	table := NewTable(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) { return conn, nil }})
	t.Cleanup(func() { _ = remote.Close(); _ = table.Close() })
	old := NewSourceChan(nil, nil)
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	key := pkt.Src().(netapi.Address).Comparable()
	table.sourceControl.Store(key, old)
	old.loopStopTime.Store(new(time.Now().Add(-time.Hour)))
	if !old.retireIdle(time.Second) {
		t.Fatal("idle source not retired")
	}
	if err := table.Write(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, conn.writing)
	awaitClosed(t, old.done)
	current, _ := table.sourceControl.Load(key)
	if current == old {
		t.Fatal("admitted packet to retired source")
	}
}

func TestCleanerCannotRetireDialingSource(t *testing.T) {
	dialing := make(chan struct{})
	source := NewSourceChan(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) { close(dialing); <-ctx.Done(); return nil, ctx.Err() }})
	defer source.Close()
	source.loopStopTime.Store(new(time.Now().Add(-time.Hour)))
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	if err := source.WritePacket(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, dialing)
	if source.retireIdle(time.Second) {
		t.Fatal("cleaner canceled a dial in progress")
	}
}

func TestMigrationCancelsBlockedReplyAndRetriesOnNewTransport(t *testing.T) {
	local, remote := net.Pipe()
	conn := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	table := NewTable(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) { return conn, nil }})
	t.Cleanup(func() { _ = remote.Close(); _ = table.Close() })
	started := make(chan struct{})
	dst, _ := netapi.ParseAddressPort("udp", "192.0.2.20", 443)
	src := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	enqueue := func(write netapi.WriteBack) {
		pkt := netapi.NewPacket(src, dst, pool.Clone([]byte("request")), write, netapi.WithMigrateID(8754))
		err := table.Write(t.Context(), pkt)
		pkt.DecRef()
		if err != nil {
			t.Fatal(err)
		}
	}
	enqueue(&contextReplyWriter{write: netapi.WriteBackContextFunc(func(ctx context.Context, _ []byte, _ net.Addr) (int, error) {
		close(started)
		<-ctx.Done()
		return 0, ctx.Err()
	})})
	awaitClosed(t, conn.reading)
	if _, err := remote.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, started)
	delivered := make(chan string, 1)
	enqueue(&contextReplyWriter{write: netapi.WriteBackContextFunc(func(_ context.Context, b []byte, _ net.Addr) (int, error) { delivered <- string(b); return len(b), nil })})
	select {
	case got := <-delivered:
		if got != "reply" {
			t.Fatalf("reply=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("migration did not unblock and retry reply")
	}
	select {
	case <-conn.closed:
		t.Fatal("migration closed shared outbound socket")
	default:
	}
}

// A stable comparable writer models a UOT stream. Different streams can share
// exactly the same source address when carried by HTTP/2 or a multiplexer.
type contextReplyWriter struct{ write netapi.WriteBackContextFunc }

func (w *contextReplyWriter) WriteBack(b []byte, a net.Addr) (int, error) {
	return w.write(context.Background(), b, a)
}
func (w *contextReplyWriter) WriteBackContext(ctx context.Context, b []byte, a net.Addr) (int, error) {
	return w.write(ctx, b, a)
}

func TestReplyWriterIdentitySurvivesFreshAddressObjects(t *testing.T) {
	source := NewSourceChan(nil, nil)
	defer source.Close()
	writer := &contextReplyWriter{}
	dst, _ := netapi.ParseAddressPort("udp", "192.0.2.20", 443)
	packet := func() *netapi.Packet {
		return netapi.NewPacket(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}, dst, nil, writer)
	}
	first, next := packet(), packet()
	defer first.DecRef()
	defer next.DecRef()
	source.bindReply(first)
	binding := source.reply.Load()
	source.bindReply(next)
	if binding.ctx.Err() != nil || source.reply.Load() != binding {
		t.Fatal("same transport was canceled because its address pointer changed")
	}
}

func TestUndeliverableRepliesDoNotCloseUDPSession(t *testing.T) {
	local, remote := net.Pipe()
	conn := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	u := NewSourceChan(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) { return conn, nil }})
	t.Cleanup(func() { _ = remote.Close(); _ = u.Close() })

	const rejected = 20 // Exceeds the old consecutive transport-error threshold.
	var calls atomic.Int32
	delivered := make(chan int, rejected+1)
	base := lifecyclePacket()
	pkt := netapi.NewPacket(base.Src(), base.Dst(), pool.Clone(base.GetPayload()), netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) {
		n := int(calls.Add(1))
		delivered <- n
		if n <= rejected {
			return 0, fmt.Errorf("%w: test datagram", netapi.ErrUndeliverableDatagram)
		}
		return len(b), nil
	}))
	base.DecRef()
	if err := u.WritePacket(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	pkt.DecRef()
	awaitClosed(t, conn.reading)
	awaitClosed(t, conn.writing)

	for i := 1; i <= rejected+1; i++ {
		if _, err := remote.Write([]byte("reply")); err != nil {
			t.Fatalf("reply %d: outbound socket closed: %v", i, err)
		}
		select {
		case n := <-delivered:
			if n != i {
				t.Fatalf("reply order: got %d, want %d", n, i)
			}
		case <-time.After(time.Second):
			t.Fatalf("reply %d not delivered", i)
		}
	}
	select {
	case <-conn.closed:
		t.Fatal("single-packet reply errors closed a healthy outbound UDP socket")
	default:
	}
}
