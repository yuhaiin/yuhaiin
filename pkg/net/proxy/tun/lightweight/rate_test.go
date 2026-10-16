package lightweight

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"testing"
	"testing/synctest"
	"time"
)

type rateRecorder struct {
	congestion.Controller
	window uint64
	last   congestion.AckEvent
}

func (r *rateRecorder) CongestionWindow() uint64    { return r.window }
func (r *rateRecorder) OnAck(e congestion.AckEvent) { r.last = e; r.Controller.OnAck(e) }

func TestDeliveryRateUsesCurrentFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000, "reno")
		c.mu.Lock()
		recorder := &rateRecorder{Controller: c.controller, window: 4 * 1460}
		c.controller = recorder
		c.mu.Unlock()
		if _, err := c.Write(make([]byte, 100*1460)); err != nil {
			t.Fatal(err)
		}
		for range 4 {
			_ = peerPacket(t, peer)
		}
		for i := range 80 {
			time.Sleep(10 * time.Millisecond)
			_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+uint32((i+1)*1460), flagACK, 10000, nil, nil))
			_ = peerPacket(t, peer)
		}
		c.mu.Lock()
		event := recorder.last
		c.mu.Unlock()
		if event.DeliveryRate < 100000 || event.DeliveryRate > 200000 {
			t.Fatalf("steady 146000 B/s flight sampled as %d B/s", event.DeliveryRate)
		}
	})
}

func TestPacedBacklogIsNotApplicationLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, peer, seq := passiveWire(t, 100, 10000, "reno")
		c.mu.Lock()
		recorder := &rateRecorder{Controller: c.controller, window: 1 << 20}
		c.controller = recorder
		c.mu.Unlock()
		if _, err := c.Write(make([]byte, 4*1460)); err != nil {
			t.Fatal(err)
		}
		for range 4 {
			_ = peerPacket(t, peer)
		}
		_ = peer.WritePacket(wireTCP(c.key.remote, c.key.local, 101, seq+1460, flagACK, 10000, nil, nil))
		synctest.Wait()
		c.mu.Lock()
		limited := recorder.last.AppLimited
		c.mu.Unlock()
		if limited {
			t.Fatal("packet sent with queued backlog was labeled application limited solely because cwnd was large")
		}
	})
}

func TestPacingLateWakePreservesBoundedCredit(t *testing.T) {
	start := time.Unix(100, 0)
	due := pacingDeadline(start, time.Time{}, 1000, 10_000_000)
	now := start.Add(10 * time.Millisecond) // A delayed timer/idle writer, not ten milliseconds of usable credit.
	burst := 0
	for !due.After(now) && burst < 100 {
		due = pacingDeadline(now, due, 1000, 10_000_000)
		burst++
	}
	if burst < 2 || burst > 11 || !due.After(now) {
		t.Fatalf("late pacing burst=%d due=%s", burst, due.Sub(now))
	}
	// Long idle periods must not increase the burst allowance.
	now = now.Add(time.Hour)
	burst = 0
	for !due.After(now) && burst < 100 {
		due = pacingDeadline(now, due, 1000, 10_000_000)
		burst++
	}
	if burst > 11 {
		t.Fatal("idle pacing credit accumulated without bound")
	}
}
