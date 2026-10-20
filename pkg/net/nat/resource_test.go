package nat

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func resourcePacket(t *testing.T, port int) *netapi.Packet {
	t.Helper()
	dst, err := netapi.ParseAddressPort("udp", "192.0.2.5", 5353)
	if err != nil {
		t.Fatal(err)
	}
	return netapi.NewPacket(
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: port},
		dst, []byte("test"),
		netapi.WriteBackFunc(func(p []byte, _ net.Addr) (int, error) { return len(p), nil }),
	)
}

func TestNATQueueBytesStayChargedDuringDial(t *testing.T) {
	started := make(chan struct{})
	dialer := lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	budget := trafficcontrol.NewGovernor(trafficcontrol.Limits{MaxQueueBytes: 4096}, nil)
	source := NewSourceChan(nil, dialer)
	source.queueBudget = budget
	t.Cleanup(func() { _ = source.Close() })

	pkt := resourcePacket(t, 30010)
	if err := source.WritePacket(t.Context(), pkt); err != nil {
		t.Fatal(err)
	}
	pkt.DecRef()
	awaitClosed(t, started)
	if got := budget.Snapshot().QueueBytes; got != int64(len("test")) {
		t.Fatalf("in-flight payload was not charged: %d bytes", got)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if got := budget.Snapshot().QueueBytes; got != 0 {
		t.Fatalf("payload reservation leaked after cancellation: %d bytes", got)
	}
}

func TestNATQueueBytesStayChargedDuringResolution(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var lookupCount atomic.Int32
	resolver := lookupResolver{lookup: func(ctx context.Context, _ string) (*netapi.IPs, error) {
		if lookupCount.Add(1) == 1 {
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
	budget := trafficcontrol.NewGovernor(trafficcontrol.Limits{MaxQueueBytes: 4}, nil)
	source.queueBudget = budget
	dst, err := netapi.ParseAddressPort("udp", "charged.test", 443)
	if err != nil {
		t.Fatal(err)
	}
	enqueueResolutionPacket(t, source, dst, []byte("test"))
	awaitClosed(t, started)
	if got := budget.Snapshot().QueueBytes; got != 4 {
		t.Fatalf("in-flight resolution bytes = %d, want 4", got)
	}

	src, _ := netapi.ParseAddressPort("udp", "192.0.2.1", 6000)
	excess := netapi.NewPacket(src, dst, []byte("x"), netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { return len(b), nil }))
	if err := source.WritePacket(t.Context(), excess); !errors.Is(err, ErrSendPacketQueueFull) {
		t.Fatalf("over-budget packet admitted during resolution: %v", err)
	}
	excess.DecRef()

	releaseOnce()
	if got := receiveRecorded(t, sent); string(got.data) != "test" {
		t.Fatalf("resolved packet = %q", got.data)
	}
	waitForSourcePending(t, source)
	if got := budget.Snapshot().QueueBytes; got != 0 {
		t.Fatalf("resolution reservation leaked after send: %d bytes", got)
	}
}

type routeAwareTestProxy struct {
	*testProxy
	conn    *testPacketConn
	routeID string
}

func (p *routeAwareTestProxy) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	netapi.GetContext(ctx).SetMatchedRule(p.routeID, "test route")
	return p.conn, nil
}

func waitForSourcePending(t *testing.T, source *SourceControl) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for source.pending.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("UDP packet did not finish processing")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForRouteDrop(t *testing.T, m *trafficcontrol.Manager, direction trafficcontrol.Direction) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		usage := m.Usage()
		if direction == trafficcontrol.Upload && usage.RejectedUploadDatagrams != 0 || direction == trafficcontrol.Download && usage.RejectedDownloadDatagrams != 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("route profile did not reject the datagram")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestNATRouteProfileUsesSelectedRouteForBothDirections(t *testing.T) {
	for _, direction := range []trafficcontrol.Direction{trafficcontrol.Upload, trafficcontrol.Download} {
		name := map[trafficcontrol.Direction]string{trafficcontrol.Upload: "upload", trafficcontrol.Download: "download"}[direction]
		t.Run(name, func(t *testing.T) {
			profile := trafficcontrol.Profile{}
			rate := trafficcontrol.Rate{BytesPerSecond: 1, BurstBytes: 2}
			if direction == trafficcontrol.Upload {
				profile.Upload = rate
			} else {
				profile.Download = rate
			}
			manager := trafficcontrol.NewManager()
			if err := manager.Apply(trafficcontrol.Config{
				Enabled:       true,
				Profiles:      map[string]trafficcontrol.Profile{"limited": profile},
				RouteProfiles: map[string]string{"selected-route": "limited"},
			}); err != nil {
				t.Fatal(err)
			}

			packetConn := &testPacketConn{t: t, ip: true}
			dialer := &routeAwareTestProxy{
				testProxy: &testProxy{t: t},
				conn:      packetConn,
				routeID:   "selected-route",
			}
			source := NewSourceChan(nil, dialer)
			source.trafficControl = manager
			t.Cleanup(func() { _ = source.Close() })

			dst, err := netapi.ParseAddressPort("udp", "192.0.2.5", 5353)
			if err != nil {
				t.Fatal(err)
			}
			src := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 30011}
			var replies atomic.Int64
			pkt := netapi.NewPacket(src, dst, []byte("test"), netapi.WriteBackFunc(func(p []byte, _ net.Addr) (int, error) {
				replies.Add(1)
				return len(p), nil
			}), netapi.WithInboundID("inbound"))
			if err := source.WritePacket(t.Context(), pkt); err != nil {
				t.Fatal(err)
			}
			pkt.DecRef()

			waitForRouteDrop(t, manager, direction)
			waitForSourcePending(t, source)
			if direction == trafficcontrol.Upload {
				packetConn.mu.Lock()
				written := packetConn.write
				packetConn.mu.Unlock()
				if written {
					t.Fatal("UDP datagram bypassed the selected route profile")
				}
			} else if replies.Load() != 0 {
				t.Fatal("UDP reply bypassed the selected route profile")
			}
		})
	}
}

func TestNATSessionLimitAndShutdownRelease(t *testing.T) {
	table := NewTable(nil, &testProxy{t: t})
	table.budget = trafficcontrol.NewGovernor(trafficcontrol.Limits{MaxSessions: 1, MaxQueueBytes: 4096}, nil)
	p1 := resourcePacket(t, 30001)
	p2 := resourcePacket(t, 30002)
	ctx := netapi.WithContext(t.Context())
	err := table.Write(ctx, p1)
	p1.DecRef()
	if err != nil {
		t.Fatal("first session", err)
	}
	err = table.Write(ctx, p2)
	p2.DecRef()
	if !errors.Is(err, ErrNATSessionLimit) {
		t.Fatalf("expected limit, got %v", err)
	}
	if stats := table.ResourceStats(); stats.Sessions != 1 || stats.DeniedSessions == 0 {
		t.Fatal(stats)
	}
	if err := table.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := table.ResourceStats(); stats.Sessions != 0 || stats.QueueBytes != 0 {
		t.Fatal("leak after close", stats)
	}
}

func TestNATQueueByteBudgetAndShutdownRelease(t *testing.T) {
	table := NewTable(nil, &testProxy{t: t})
	table.budget = trafficcontrol.NewGovernor(trafficcontrol.Limits{MaxSessions: 2, MaxQueueBytes: 1}, nil)
	p := resourcePacket(t, 30003)
	err := table.Write(netapi.WithContext(t.Context()), p)
	p.DecRef()
	if !errors.Is(err, ErrSendPacketQueueFull) {
		t.Fatalf("expected bytes cap, got %v", err)
	}
	if stats := table.ResourceStats(); stats.DeniedBytes == 0 || stats.QueueBytes != 0 {
		t.Fatal(stats)
	}
	if err := table.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := table.ResourceStats(); stats.Sessions != 0 {
		t.Fatal(stats)
	}
}

func BenchmarkNATSessionReservation(b *testing.B) {
	g := trafficcontrol.NewGovernor(trafficcontrol.Limits{MaxSessions: 16384}, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		lease, ok := g.AcquireSession()
		if !ok {
			b.Fatal("session budget")
		}
		lease.Release()
	}
}

func TestPendingResolutionBytesAreChargedUntilDrain(t *testing.T) {
	g := trafficcontrol.NewGovernor(trafficcontrol.Limits{MaxQueueBytes: 4}, nil)
	u := &SourceControl{queueBudget: g, resolutions: make(map[uint64]*pendingResolution)}
	packet := netapi.NewPacket(nil, nil, []byte("test"), nil)
	p := &pendingResolution{key: 1}
	if !g.ReservePendingTask() {
		t.Fatal("failed to reserve pending task")
	}
	if err := u.appendResolution(p, packet); err != nil {
		t.Fatal(err)
	}
	u.resolutions[p.key] = p
	if got := g.Snapshot(); got.QueueBytes != 4 {
		t.Fatal(got)
	}
	second := netapi.NewPacket(nil, nil, []byte("second"), nil)
	if err := u.appendResolution(p, second); !errors.Is(err, ErrSendPacketQueueFull) {
		t.Fatalf("expected queue cap: %v", err)
	}
	u.drainResolutions()
	if got := g.Snapshot(); got.QueueBytes != 0 || got.PendingTasks != 0 {
		t.Fatal("bytes leaked after cancellation", got)
	}
	packet.DecRef()
	second.DecRef()
}
