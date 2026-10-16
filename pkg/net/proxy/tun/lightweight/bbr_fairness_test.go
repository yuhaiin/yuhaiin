//go:build lightweight_qualification

package lightweight

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// All endpoints share the same serialization queues and propagation scheduler.
// Giving each flow its own simulatedIO would provide independent bandwidth and
// could not test coexistence or starvation at a shared bottleneck.
type sharedTestLink struct {
	wire      *simulatedIO
	endpoints map[netip.Addr]*sharedTestEndpoint
	wg        sync.WaitGroup
}
type sharedTestEndpoint struct {
	hub      *sharedTestLink
	incoming chan []byte
	done     chan struct{}
	once     sync.Once
}

func newSharedTestLink(base PacketIO, p linkProfile, addresses []netip.Addr) *sharedTestLink {
	h := &sharedTestLink{wire: simulate(base, p), endpoints: make(map[netip.Addr]*sharedTestEndpoint)}
	for _, a := range addresses {
		h.endpoints[a] = &sharedTestEndpoint{hub: h, incoming: make(chan []byte, 256), done: make(chan struct{})}
	}
	h.wg.Go(func() {
		b := make([]byte, 65575)
		for {
			n, err := h.wire.ReadPacket(b)
			if err != nil {
				return
			}
			packet, err := ParsePacket(b[:n])
			if err != nil {
				continue
			}
			if e := h.endpoints[packet.Destination]; e != nil {
				select {
				case e.incoming <- bytes.Clone(b[:n]):
				case <-e.done:
				case <-h.wire.done:
					return
				}
			}
		}
	})
	return h
}
func (h *sharedTestLink) Close() { _ = h.wire.Close(); h.wg.Wait() }
func (e *sharedTestEndpoint) ReadPacket(b []byte) (int, error) {
	select {
	case p := <-e.incoming:
		return copy(b, p), nil
	case <-e.done:
		return 0, net.ErrClosed
	case <-e.hub.wire.done:
		return 0, net.ErrClosed
	}
}
func (e *sharedTestEndpoint) WritePacket(b []byte) error {
	select {
	case <-e.done:
		return net.ErrClosed
	default:
		return e.hub.wire.WritePacket(b)
	}
}
func (e *sharedTestEndpoint) Close() error { e.once.Do(func() { close(e.done) }); return nil }

func TestBBRSharedBottleneck(t *testing.T) {
	for _, p := range []linkProfile{
		{name: "rtt50ms-10Mbps-queue32", rtt: 50 * time.Millisecond, bytesPerSecond: 1250000, queue: 32, mtu: 1500},
		{name: "rtt200ms-loss0.1pct-10Mbps-queue64", rtt: 200 * time.Millisecond, bytesPerSecond: 1250000, lossPPM: 1000, queue: 64, mtu: 1500},
		{name: "rtt100ms-loss1pct-10Mbps-queue64", rtt: 100 * time.Millisecond, bytesPerSecond: 1250000, lossPPM: 10000, queue: 64, mtu: 1500},
	} {
		t.Run(p.name, func(t *testing.T) { runSharedBBR(t, p, false) })
	}
}
func TestBBRBandwidthChanges(t *testing.T) {
	runSharedBBR(t, linkProfile{name: "rate10-5-10Mbps", rtt: 100 * time.Millisecond, bytesPerSecond: 1250000, queue: 32, mtu: 1500}, true)
}
func runSharedBBR(t *testing.T, p linkProfile, changeRate bool) {
	controlRate := float64(0)
	bbrControl := float64(0)
	if p.lossPPM > 0 {
		// A loss-based sender may not be able to use an equal nominal share even
		// alone. Measure that capability instead of tuning BBR to suppress it.
		t.Run("cubic-control", func(t *testing.T) { controlRate = runBBRTrial(t, p, false, []string{"cubic"}, false, 0, 0) })
		t.Run("bbr-control", func(t *testing.T) { bbrControl = runBBRTrial(t, p, false, []string{"bbr"}, false, 0, 0) })
	}
	t.Run("sharing", func(t *testing.T) {
		runBBRTrial(t, p, changeRate, []string{"bbr", "bbr", "cubic"}, true, controlRate, bbrControl)
	})
}
func runBBRTrial(t *testing.T, p linkProfile, changeRate bool, kinds []string, enforceSharing bool, cubicControl, bbrControl float64) float64 {
	t.Helper()
	// Hosts differ in timer precision and throughput. CI checks data and continued
	// progress; explicit local qualification additionally enforces the reported
	// performance/fairness thresholds. Both paths retain all measured metrics.
	thresholds := enforceSharing && os.Getenv("LIGHTWEIGHT_NETWORK_QUALIFY") == "1"
	ref, err := newReferenceIO(1500)
	if err != nil {
		t.Fatal(err)
	}
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4")}
	addresses = addresses[:len(kinds)]
	hub := newSharedTestLink(ref, p, addresses)
	defer hub.Close()
	dst := netip.MustParseAddrPort("192.0.2.2:8080")
	a, proto := refAddress(dst)
	listener, err := gonet.ListenTCP(ref.stack, a, proto)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var stacks []*Stack
	var clients []*TCPConn
	var servers []net.Conn
	var wg sync.WaitGroup
	// Cleanup must interrupt workers even if a correctness assertion fails.
	defer func() {
		for _, s := range stacks {
			_ = s.Close()
		}
		for _, s := range servers {
			_ = s.Close()
		}
		wg.Wait()
	}()
	counts := make([]atomic.Uint64, len(kinds))
	for i, kind := range kinds {
		s, err := New(Config{Addresses: []netip.Addr{addresses[i]}, CongestionControl: kind, Profile: RemoteTunnel}, hub.endpoints[addresses[i]])
		if err != nil {
			t.Fatal(err)
		}
		stacks = append(stacks, s)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		conn, err := s.DialContextTCP(ctx, dst)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		peer, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, conn.(*TCPConn))
		servers = append(servers, peer)
	}
	start := make(chan struct{})
	errors := make(chan error, 6)
	end := time.Now().Add(45 * time.Second)
	payload := bytes.Repeat([]byte{0xa5}, 16<<10)
	for i, c := range clients {
		peer := servers[i]
		_ = c.SetDeadline(end)
		_ = peer.SetDeadline(end)
		wg.Go(func() {
			<-start
			for {
				if _, err := c.Write(payload); err != nil {
					errors <- err
					return
				}
			}
		})
		wg.Go(func() {
			buf := make([]byte, len(payload))
			<-start
			for {
				n, err := peer.Read(buf)
				if n > 0 {
					if !bytes.Equal(buf[:n], payload[:n]) {
						errors <- fmt.Errorf("flow %d payload corruption", i)
						return
					}
					counts[i].Add(uint64(n))
				}
				if err != nil {
					errors <- err
					return
				}
			}
		})
	}
	trialStart := time.Now()
	close(start)
	// Several 2-3 second v3 probe cycles are needed to assess coexistence.
	// Record startup separately rather than calling a one-second warmup steady.
	warmup := 4*time.Second + 4*p.rtt
	timer := time.NewTimer(warmup)
	<-timer.C // Same warmup interval for all flows.
	baseline := make([]uint64, len(counts))
	for i := range counts {
		baseline[i] = counts[i].Load()
	}
	t.Logf("startup-duration=%s delivered=%v", time.Since(trialStart), baseline)
	warmupCapacity := time.Since(trialStart).Seconds() * float64(p.bytesPerSecond)
	capacity := float64(0)
	last := time.Now()
	measurementStart := last
	previous := append([]uint64(nil), baseline...)
	for phase := range 3 {
		rate := p.bytesPerSecond
		if changeRate && phase == 1 {
			rate /= 2
		}
		hub.wire.mu.Lock()
		hub.wire.profile.bytesPerSecond = rate
		hub.wire.mu.Unlock()
		timer.Reset(10 * time.Second)
		select {
		case err := <-errors:
			t.Fatalf("flow stopped before measurement ended: %v", err)
		case <-timer.C:
		}
		now := time.Now()
		capacity += now.Sub(last).Seconds() * float64(rate)
		last = now
		var delivered []uint64
		for i := range counts {
			current := counts[i].Load()
			if current == previous[i] {
				t.Errorf("flow %d (%s) made no progress in phase %d", i, kinds[i], phase)
			}
			previous[i] = current
			delivered = append(delivered, current-baseline[i])
		}
		t.Logf("phase=%d bottleneck=%d B/s cumulative-delivered=%v drops=%d", phase, rate, delivered, hub.wire.drops.Load())
	}
	sum, squared := float64(0), float64(0)
	bbrSum, bbrSquared := float64(0), float64(0)
	bbrCount := 0
	relativeSum, relativeSquared := float64(0), float64(0)
	totalPayload := float64(0)
	seconds := last.Sub(measurementStart).Seconds()
	for i := range counts {
		current := counts[i].Load()
		totalPayload += float64(current)
		n := float64(current - baseline[i])
		sum += n
		squared += n * n
		if kinds[i] == "bbr" {
			bbrSum += n
			bbrSquared += n * n
			bbrCount++
		}
		minimum := capacity * .1
		if kinds[i] == "cubic" && cubicControl > 0 {
			achievable := min(cubicControl, capacity/seconds/float64(len(kinds)))
			minimum = achievable * seconds / float64(len(kinds))
			t.Logf("CUBIC standalone=%.0f B/s mixed=%.0f B/s achievable-share=%.0f B/s", cubicControl, n/seconds, achievable)
		}
		solo := bbrControl
		if kinds[i] == "cubic" {
			solo = cubicControl
		}
		if solo > 0 {
			relative := n / seconds / solo
			relativeSum += relative
			relativeSquared += relative * relative
		}
		if n == 0 || thresholds && n < minimum {
			t.Errorf("flow %d (%s) starved: %.0f bytes; measured-share floor %.0f", i, kinds[i], n, minimum)
		}
		clients[i].mu.Lock()
		if snapshot, ok := clients[i].controller.(interface{ Snapshot() congestion.BBRSnapshot }); ok {
			t.Logf("flow=%d model=%+v", i, snapshot.Snapshot())
		}
		clients[i].mu.Unlock()
	}
	fairness := sum * sum / (float64(len(kinds)) * squared)
	utilization := totalPayload / (capacity + warmupCapacity)
	t.Logf("jain=%.3f trial-payload-utilization=%.3f measured-payload=%.0f measured-capacity=%.0f", fairness, utilization, sum, capacity)
	if enforceSharing && bbrCount > 1 {
		bbrJain := bbrSum * bbrSum / (float64(bbrCount) * bbrSquared)
		t.Logf("BBR intra-algorithm jain=%.3f", bbrJain)
		if thresholds && bbrJain < .8 {
			t.Errorf("BBR intra-algorithm fairness %.3f < 0.8", bbrJain)
		}
	}
	if enforceSharing && relativeSquared > 0 {
		relativeJain := relativeSum * relativeSum / (float64(len(kinds)) * relativeSquared)
		t.Logf("standalone-normalized mixed jain=%.3f", relativeJain)
		if thresholds && relativeJain < .8 {
			t.Errorf("standalone-normalized mixed fairness %.3f < 0.8", relativeJain)
		}
	}
	if thresholds && cubicControl == 0 && fairness < .8 {
		t.Errorf("shared bottleneck fairness %.3f < 0.8", fairness)
	}
	if thresholds && utilization < .5 {
		t.Errorf("shared bottleneck payload utilization %.3f < 0.5", utilization)
	}
	return sum / seconds
}
