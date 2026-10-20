package nat

import (
	"context"
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type lookupResolver struct {
	netapi.Resolver
	lookup func(context.Context, string) (*netapi.IPs, error)
}

func (r lookupResolver) LookupIP(ctx context.Context, domain string, _ ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return r.lookup(ctx, domain)
}

type recordedPacket struct {
	destination net.Addr
	data        []byte
}
type recordingPacketConn struct {
	*lifecyclePacketConn
	sent chan recordedPacket
}

func (c recordingPacketConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	c.sent <- recordedPacket{dst, append([]byte(nil), b...)}
	return len(b), nil
}

func resolutionTestSource(t *testing.T, resolver netapi.Resolver) (*SourceControl, <-chan recordedPacket) {
	t.Helper()
	local, remote := net.Pipe()
	sent := make(chan recordedPacket, 512)
	base := &lifecyclePacketConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	source := NewSourceChan(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		netapi.GetContext(ctx).ConnOptions().Resolver().SetResolver(resolver)
		return recordingPacketConn{base, sent}, nil
	}})
	t.Cleanup(func() { _ = remote.Close(); _ = source.Close() })
	return source, sent
}
func enqueueResolutionPacket(t *testing.T, source *SourceControl, dst netapi.Address, data []byte) *netapi.Packet {
	t.Helper()
	src, _ := netapi.ParseAddressPort("udp", "192.0.2.1", 6000)
	pkt := netapi.NewPacket(src, dst, pool.Clone(data), netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { return len(b), nil }))
	err := source.WritePacket(t.Context(), pkt)
	pkt.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}
func receiveRecorded(t *testing.T, packets <-chan recordedPacket) recordedPacket {
	t.Helper()
	select {
	case pkt := <-packets:
		return pkt
	case <-time.After(time.Second):
		t.Fatal("packet not sent")
		return recordedPacket{}
	}
}

func TestDNSResolutionPreservesOrderAndCoalescesLookup(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var lookups atomic.Int32
	resolver := lookupResolver{lookup: func(ctx context.Context, _ string) (*netapi.IPs, error) {
		if lookups.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return &netapi.IPs{A: []net.IP{net.IPv4(192, 0, 2, 20)}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	source, sent := resolutionTestSource(t, resolver)
	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseOnce)
	dst, _ := netapi.ParseAddressPort("udp", "ordered.test", 443)
	var packets []*netapi.Packet
	for i := range 32 {
		packets = append(packets, enqueueResolutionPacket(t, source, dst, []byte{byte(i)}))
	}
	awaitClosed(t, started)
	// A ready IP traverses the sender after the domain packets were admitted.
	// Receiving it proves pending destinations do not block that sender.
	ready, _ := netapi.ParseAddressPort("udp", "192.0.2.99", 443)
	enqueueResolutionPacket(t, source, ready, []byte("ready"))
	if got := receiveRecorded(t, sent); got.destination.String() != ready.String() {
		t.Fatalf("ready target=%s", got.destination)
	}
	releaseOnce()
	for i := range 32 {
		got := receiveRecorded(t, sent)
		if len(got.data) != 1 || got.data[0] != byte(i) {
			t.Fatalf("packet %d=%v", i, got.data)
		}
	}
	if lookups.Load() != 1 {
		t.Fatalf("lookups=%d", lookups.Load())
	}
	_ = source.Close()
	for _, pkt := range packets {
		if pkt.GetPayload() != nil {
			t.Fatal("processed packet retained")
		}
	}
}

func TestDNSResolutionConcurrencyBoundAndShutdown(t *testing.T) {
	var active, peak atomic.Int32
	started := make(chan struct{}, 16)
	resolver := lookupResolver{lookup: func(ctx context.Context, _ string) (*netapi.IPs, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	source, sent := resolutionTestSource(t, resolver)
	var packets []*netapi.Packet
	for i := range 12 {
		dst, _ := netapi.ParseAddressPort("udp", fmt.Sprintf("pending-%d.test", i), 443)
		packets = append(packets, enqueueResolutionPacket(t, source, dst, []byte("pending")))
	}
	ready, _ := netapi.ParseAddressPort("udp", "192.0.2.99", 443)
	enqueueResolutionPacket(t, source, ready, []byte("ready"))
	receiveRecorded(t, sent)
	for range maxConcurrentResolutions {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("lookup not started")
		}
	}
	if peak.Load() != maxConcurrentResolutions {
		t.Fatalf("parallel lookups=%d", peak.Load())
	}
	_ = source.Close()
	if active.Load() != 0 || source.pending.Load() != 0 {
		t.Fatalf("after close: lookups=%d pending=%d", active.Load(), source.pending.Load())
	}
	for _, pkt := range packets {
		if pkt.GetPayload() != nil {
			t.Fatal("pending resolution retained payload")
		}
	}
}

func TestDNSResolutionQueueBound(t *testing.T) {
	// Exercise admission independently of network timing. This source has no
	// concurrent run goroutine and every retained reference is drained below.
	source := &SourceControl{queueBudget: trafficcontrol.UnlimitedBudget(), resolutions: make(map[uint64]*pendingResolution)}
	pending := new(pendingResolution)
	defer source.drainResolutions()
	source.resolutions[1] = pending
	var packets []*netapi.Packet
	for range maxPendingPackets() {
		pkt := lifecyclePacket()
		packets = append(packets, pkt)
		if err := source.appendResolution(pending, pkt); err != nil {
			t.Fatal(err)
		}
		pkt.DecRef()
	}
	excess := lifecyclePacket()
	defer excess.DecRef()
	if err := source.appendResolution(pending, excess); !errors.Is(err, ErrSendPacketQueueFull) {
		t.Fatalf("overflow=%v", err)
	}
	source.drainResolutions()
	for _, pkt := range packets {
		if pkt.GetPayload() != nil {
			t.Fatal("pending packet retained after drain")
		}
	}
}

func TestDNSResolutionFailureCanRetry(t *testing.T) {
	failed := make(chan struct{})
	var calls atomic.Int32
	resolver := lookupResolver{lookup: func(context.Context, string) (*netapi.IPs, error) {
		if n := calls.Add(1); n <= 2 {
			if n == 1 {
				close(failed)
			}
			return nil, errors.New("resolver unavailable")
		}
		return &netapi.IPs{A: []net.IP{net.IPv4(192, 0, 2, 20)}}, nil
	}}
	source, sent := resolutionTestSource(t, resolver)
	dst, _ := netapi.ParseAddressPort("udp", "retry.test", 443)
	first := enqueueResolutionPacket(t, source, dst, []byte("failed"))
	awaitClosed(t, failed)
	// Wait for the failed request to be released before retrying the same key.
	deadline := time.Now().Add(time.Second)
	for first.GetPayload() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if first.GetPayload() != nil {
		t.Fatal("failed resolution was not released")
	}
	enqueueResolutionPacket(t, source, dst, []byte("retry"))
	if got := receiveRecorded(t, sent); string(got.data) != "retry" {
		t.Fatalf("sent %q", got.data)
	}
}

func TestStaleDNSResultRetriesOnReplacementConnection(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	oldResolver := lookupResolver{lookup: func(ctx context.Context, _ string) (*netapi.IPs, error) {
		close(started)
		select {
		case <-release:
			return &netapi.IPs{A: []net.IP{net.IPv4(192, 0, 2, 10)}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	newResolver := lookupResolver{lookup: func(context.Context, string) (*netapi.IPs, error) {
		return &netapi.IPs{A: []net.IP{net.IPv4(192, 0, 2, 11)}}, nil
	}}
	firstLocal, firstRemote := net.Pipe()
	nextLocal, nextRemote := net.Pipe()
	first := &lifecyclePacketConn{Conn: firstLocal, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	next := &lifecyclePacketConn{Conn: nextLocal, reading: make(chan struct{}), writing: make(chan struct{}), closed: make(chan struct{})}
	sent := make(chan recordedPacket, 4)
	dials := 0
	source := NewSourceChan(nil, lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		dials++
		if dials == 1 {
			netapi.GetContext(ctx).ConnOptions().Resolver().SetResolver(oldResolver)
			return recordingPacketConn{first, sent}, nil
		}
		netapi.GetContext(ctx).ConnOptions().Resolver().SetResolver(newResolver)
		return recordingPacketConn{next, sent}, nil
	}})
	t.Cleanup(func() { releaseOnce(); _ = firstRemote.Close(); _ = nextRemote.Close(); _ = source.Close() })
	domain, _ := netapi.ParseAddressPort("udp", "changed.test", 443)
	enqueue := func(src net.Addr, dst netapi.Address, data string) {
		pkt := netapi.NewPacket(src, dst, pool.Clone([]byte(data)), netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { return len(b), nil }), netapi.WithMigrateID(4455))
		err := source.WritePacket(t.Context(), pkt)
		pkt.DecRef()
		if err != nil {
			t.Fatal(err)
		}
	}
	oldSource := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	newSource := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	enqueue(oldSource, domain, "pending")
	awaitClosed(t, started)
	_ = firstRemote.Close()
	awaitClosed(t, first.closed)
	ready, _ := netapi.ParseAddressPort("udp", "192.0.2.99", 443)
	enqueue(newSource, ready, "replacement")
	if got := receiveRecorded(t, sent); string(got.data) != "replacement" {
		t.Fatalf("replacement send=%q", got.data)
	}
	releaseOnce()
	got := receiveRecorded(t, sent)
	if got.destination.String() != "192.0.2.11:443" || string(got.data) != "pending" {
		t.Fatalf("stale DNS result sent %q to %s", got.data, got.destination)
	}
	if source.reply.Load().source != newSource {
		t.Fatal("replaying pending packets reverted inbound migration")
	}
}
