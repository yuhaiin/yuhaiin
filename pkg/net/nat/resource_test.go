package nat

import (
	"errors"
	"net"
	"testing"

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
	if !g.ReservePendingTask() { t.Fatal("failed to reserve pending task") }
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
