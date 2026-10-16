package congestion

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

var customIDs atomic.Uint64

func TestControllersAndRegistry(t *testing.T) {
	for _, name := range []string{"reno", "cubic", "bbr"} {
		t.Run(name, func(t *testing.T) {
			c, err := New(name, Config{MSS: 1460})
			if err != nil {
				t.Fatal(err)
			}
			other, err := New(name, Config{MSS: 1460})
			if err != nil {
				t.Fatal(err)
			}
			before := c.CongestionWindow()
			now := time.Unix(100, 0)
			c.OnPacketSent(SentPacket{Now: now, Bytes: 1460})
			c.OnAck(AckEvent{Now: now.Add(10 * time.Millisecond), AckedBytes: 1460, RTT: 10 * time.Millisecond, DeliveryRate: 1_000_000, Delivered: 1460})
			if c.CongestionWindow() < before {
				t.Fatal("window shrank without loss")
			}
			if other.CongestionWindow() != before {
				t.Fatal("shared controller state")
			}
			c.OnLoss(LossEvent{Now: now, BytesInFlight: before})
			c.OnTimeout(TimeoutEvent{Now: now, BytesInFlight: before})
			if c.CongestionWindow() < 1460 {
				t.Fatal("window below one segment")
			}
		})
	}
	if _, err := New("bad", Config{MSS: 1460}); err == nil {
		t.Fatal("unknown accepted")
	}
	if _, err := New("reno", Config{MSS: 0}); err == nil {
		t.Fatal("invalid MSS accepted")
	}
	if err := Register("nil", nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	if err := Register("reno", func(c Config) Controller { return newReno(c) }); err == nil {
		t.Fatal("duplicate accepted")
	}
	custom := "test-custom-" + strconv.FormatUint(customIDs.Add(1), 10)
	if err := Register(custom, func(c Config) Controller { return newReno(c) }); err != nil {
		t.Fatal(err)
	}
	if _, err := New(custom, Config{MSS: 1000}); err != nil {
		t.Fatal(err)
	}
}

func TestCubicEpochAndTimeGrowth(t *testing.T) {
	for _, rtt := range []time.Duration{time.Millisecond, 100 * time.Millisecond} {
		c, _ := New("cubic", Config{MSS: 1000})
		start := time.Unix(100, 0)
		c.OnLoss(LossEvent{Now: start, BytesInFlight: 10000})
		if c.CongestionWindow() != 7000 {
			t.Fatal("CUBIC beta must be 0.7")
		}
		c.OnAck(AckEvent{Now: start, RecoveryDone: true})
		c.OnAck(AckEvent{Now: start, AckedBytes: 1000, RTT: rtt, BytesInFlight: 7000})
		early := c.CongestionWindow()
		c.OnAck(AckEvent{Now: start.Add(10 * time.Second), AckedBytes: 1000, RTT: rtt, BytesInFlight: early})
		if c.CongestionWindow() < early+400 {
			t.Fatalf("missing cubic time growth: %d -> %d", early, c.CongestionWindow())
		}
		c.OnLoss(LossEvent{Now: start.Add(11 * time.Second), BytesInFlight: c.CongestionWindow()})
		if c.(*cubic).epoch != (time.Time{}) {
			t.Fatal("loss did not reset epoch")
		}
	}
}

func TestBBRBandwidthModesAndAppLimited(t *testing.T) {
	x, _ := New("bbr", Config{MSS: 1000})
	c := x.(*bbr)
	start := time.Unix(100, 0)
	delivered := uint64(0)
	ack := func(now time.Time, rate uint64, limited bool, rtt time.Duration) {
		old := delivered
		delivered += 10000
		c.OnAck(AckEvent{Now: now, AckedBytes: 10000, PriorDelivered: old, Delivered: delivered, DeliveryRate: rate, RTT: rtt, BytesInFlight: 1000, AppLimited: limited})
	}
	for i := range 4 {
		ack(start.Add(time.Duration(i)*100*time.Millisecond), 100000, false, 100*time.Millisecond)
	}
	if c.mode != Drain {
		t.Fatalf("startup exit: %+v", c.Snapshot())
	}
	ack(start.Add(time.Second), 100000, false, 110*time.Millisecond)
	if c.mode != ProbeBW {
		t.Fatal("drain did not drain")
	}
	bw := c.bw
	ack(start.Add(2*time.Second), 1, true, 110*time.Millisecond)
	if c.bw != bw {
		t.Fatal("app limited sample polluted max bandwidth")
	}
	if c.rate == 0 || c.minRTT != 100*time.Millisecond {
		t.Fatal("missing pacing or minimum RTT")
	}
	ack(start.Add(11*time.Second), 100000, false, 120*time.Millisecond)
	if c.mode != ProbeRTT || c.window != 4000 {
		t.Fatalf("probe RTT: %+v", c.Snapshot())
	}
	ack(start.Add(12*time.Second), 100000, false, 100*time.Millisecond)
	if c.mode != ProbeBW {
		t.Fatal("probe RTT failed to restore")
	}
}

func TestRenoGrowthRecovery(t *testing.T) {
	c, _ := New("reno", Config{MSS: 1000})
	w := c.CongestionWindow()
	c.OnAck(AckEvent{AckedBytes: 1000})
	if c.CongestionWindow() != w+1000 {
		t.Fatal("slow start")
	}
	c.OnLoss(LossEvent{BytesInFlight: 12000})
	if c.CongestionWindow() != 9000 {
		t.Fatalf("fast recovery: %d", c.CongestionWindow())
	}
	c.OnAck(AckEvent{RecoveryDone: true, AckedBytes: 1000})
	if c.CongestionWindow() != 6000 {
		t.Fatal("recovery exit")
	}
	for range 6 {
		c.OnAck(AckEvent{AckedBytes: 1000})
	}
	if c.CongestionWindow() < 6900 || c.CongestionWindow() > 7100 {
		t.Fatal("congestion avoidance")
	}
	c.OnTimeout(TimeoutEvent{BytesInFlight: 12000})
	if c.CongestionWindow() != 1000 {
		t.Fatal("timeout")
	}
}
