package congestion

import (
	"math"
	"testing"
	"time"
)

func testBBR(t *testing.T) *bbr {
	t.Helper()
	x, err := New("bbr", Config{MSS: 1000, MaxWindow: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	c := x.(*bbr)
	c.random = func(uint64) uint64 { return 0 }
	return c
}
func trainedBBR(t *testing.T, phase BBRPhase) *bbr {
	t.Helper()
	c := testBBR(t)
	c.mode = ProbeBW
	c.phase = phase
	c.fullReached = true
	c.bwHi[1] = 100000
	c.minRTT = 100 * time.Millisecond
	c.probeMin = c.minRTT
	c.window = 20000
	c.rate = 100000
	c.updateGains()
	return c
}
func TestBBRVersionAndRegistry(t *testing.T) {
	c := testBBR(t)
	if c.Snapshot().Version != 3 || c.gain != 710 {
		t.Fatal("bbr is not the v3 STARTUP")
	}
	for _, name := range []string{"bbr1", "bbr2", "bbr-v1", "bbr-v2"} {
		if _, err := New(name, Config{MSS: 1000}); err == nil {
			t.Fatal("legacy BBR version remains selectable")
		}
	}
}
func TestBBRAppLimitedKeepsBandwidth(t *testing.T) {
	c := testBBR(t)
	now := time.Unix(100, 0)
	for i := range 50 {
		rate := uint64(1)
		if i == 0 {
			rate = 100000
		}
		c.OnAck(AckEvent{Now: now.Add(time.Duration(i) * time.Millisecond), AckedBytes: 1000, NewlyDelivered: 1000, RateSample: true, PriorDelivered: uint64(i * 1000), Delivered: uint64((i + 1) * 1000), SampleDelivered: 1000, DeliveryRate: rate, RTT: 100 * time.Millisecond, AppLimited: true})
	}
	if c.maxBW() != 100000 || c.mode != Startup || c.fullReached {
		t.Fatalf("app limited traffic changed path model: %+v", c.Snapshot())
	}
}
func TestBBRProbeLossBoundsAndUndo(t *testing.T) {
	c := trainedBBR(t, ProbeUp)
	now := time.Unix(100, 0)
	c.probeSamples = true
	c.OnPacketLost(LossEvent{Now: now, Delivered: 10000, LostBytes: 1000, SampleLost: 1000, TxInFlight: 20000})
	if c.phase != ProbeDown || c.probeSamples || c.inflightHi == bbrUnbounded || c.inflightHi >= 20000 {
		t.Fatalf("probe loss was not bounded: %+v", c.Snapshot())
	}
	hi := c.inflightHi
	c.OnPacketLost(LossEvent{Now: now, Delivered: 10000, LostBytes: 1000, SampleLost: 2000, TxInFlight: 20000})
	if c.inflightHi != hi {
		t.Fatal("one bandwidth probe reacted repeatedly to the same loss flight")
	}
	c.OnSpuriousLoss(AckEvent{Now: now, Delivered: 10000})
	if c.inflightHi != bbrUnbounded || c.phase != ProbeRefill || c.window < 20000 {
		t.Fatalf("spurious loss failed to restore model: %+v", c.Snapshot())
	}
}
func TestBBRCruiseLossLowerBounds(t *testing.T) {
	c := trainedBBR(t, ProbeCruise)
	c.bwLatest = 60000
	c.inflightLatest = 5000
	c.lossInRound = true
	c.adaptLowerBounds()
	if c.bwLo != 70312 || c.inflightLo != 14062 {
		t.Fatalf("v3 lower bounds: bw=%d flight=%d", c.bwLo, c.inflightLo)
	}
	c.bwLatest = 80000
	c.inflightLatest = 18000
	c.adaptLowerBounds()
	if c.bwLo < 80000 || c.inflightLo < 18000 {
		t.Fatal("loss adaptation fell below measured delivery")
	}
	for _, phase := range []BBRPhase{ProbeRefill, ProbeUp} {
		c.phase = phase
		c.resetLower()
		c.adaptLowerBounds()
		if c.bwLo != bbrUnbounded || c.inflightLo != bbrUnbounded {
			t.Fatal("probing was constrained by short-term lower bounds")
		}
	}
}
func TestBBRProbePhasesAndRenoRoundBound(t *testing.T) {
	c := trainedBBR(t, ProbeCruise)
	now := time.Unix(100, 0)
	c.cycleStamp = now
	c.probeWait = 3 * time.Second
	c.roundsSinceProbe = 9
	if c.timeToProbe(AckEvent{Now: now.Add(time.Second)}) {
		t.Fatal("probe started before time or BDP round bound")
	}
	c.roundsSinceProbe = 10
	if !c.timeToProbe(AckEvent{Now: now.Add(time.Second), Delivered: 10000}) || c.phase != ProbeRefill {
		t.Fatal("Reno coexistence round bound failed")
	}
	c.roundStart = true
	e := AckEvent{Now: now.Add(time.Second), Delivered: 20000, DeliveryRate: 100000}
	c.updateCycle(e, 1000)
	if c.phase != ProbeUp || !c.probeSamples {
		t.Fatal("REFILL did not wait a round before UP")
	}
	c.fullNow = true
	c.roundStart = false
	c.updateCycle(e, 1000)
	if c.phase != ProbeDown || c.probeWait < 2*time.Second || c.probeWait >= 3*time.Second {
		t.Fatal("full probe did not restart randomized DOWN")
	}
	c.roundStart = false
	c.roundsSinceProbe = 0
	c.fullNow = false
	c.updateCycle(AckEvent{Now: e.Now, PriorInFlight: 1000}, 1000)
	if c.phase != ProbeCruise {
		t.Fatal("drained DOWN did not reach CRUISE")
	}
	c.cycleStamp = now
	c.probeWait = 2 * time.Second
	c.roundsSinceProbe = 0
	if !c.timeToProbe(AckEvent{Now: now.Add(3 * time.Second)}) {
		t.Fatal("wall-clock probing bound failed")
	}
}
func TestBBRUpperBoundGrowthAcceleratesByRound(t *testing.T) {
	c := trainedBBR(t, ProbeUp)
	c.inflightHi = 20000
	c.raiseSlope()
	first := c.upCount
	c.raiseSlope()
	second := c.upCount
	if second >= first {
		t.Fatal("UP growth did not accelerate")
	}
	c.upCount = 1000
	c.adaptUpper(AckEvent{CwndLimited: true, TxInFlight: 20000}, 2000)
	if c.inflightHi != 22000 {
		t.Fatalf("safe ACKs did not raise upper bound: %d", c.inflightHi)
	}
}
func TestBBRStartupLossExit(t *testing.T) {
	c := testBBR(t)
	c.minRTT = 100 * time.Millisecond
	c.nextRound = 20000
	c.lossRoundDelivered = 10000
	c.lossInRound = true
	now := time.Unix(100, 0)
	for i := range 6 {
		prior := uint64(i * 1000)
		if i == 5 {
			prior = 10000
		}
		c.OnAck(AckEvent{Now: now.Add(time.Duration(i) * time.Millisecond), NewlyDelivered: 1000, AckedBytes: 1000, RateSample: true, PriorDelivered: prior, Delivered: prior + 1000, SampleDelivered: 1000, LostBytes: 1000, SampleLost: 6000, TxInFlight: 100000, BytesInFlight: 100000, DeliveryRate: 100000, RTT: 100 * time.Millisecond, InRecovery: true})
		if i < 5 && c.fullReached {
			t.Fatal("STARTUP exited before six loss-marking ACK events")
		}
	}
	if !c.fullReached || c.mode != Drain || c.inflightHi == bbrUnbounded {
		t.Fatalf("STARTUP loss exit missing: %+v", c.Snapshot())
	}
}
func TestBBRMaxWindowAndScalingBoundaries(t *testing.T) {
	x, err := New("bbr", Config{MSS: 1000, MaxWindow: 2000})
	if err != nil {
		t.Fatal(err)
	}
	c := x.(*bbr)
	now := time.Unix(100, 0)
	for i := range 20 {
		c.OnAck(AckEvent{Now: now.Add(time.Duration(i) * time.Second), AckedBytes: 1000, NewlyDelivered: 1000, Delivered: uint64((i + 1) * 1000), PriorDelivered: uint64(i * 1000), SampleDelivered: 1000, RTT: time.Millisecond, DeliveryRate: 100000, RateSample: true})
		if c.window > 2000 || c.window < 1000 {
			t.Fatalf("window escaped configured cap: %d", c.window)
		}
	}
	c.OnTimeout(TimeoutEvent{Now: now, BytesInFlight: 2000})
	if c.window > 2000 || c.window < 1000 {
		t.Fatal("timeout escaped window cap")
	}
	if scaled(math.MaxUint64, 256) != math.MaxUint64 || scaled(math.MaxUint64, 512) != math.MaxUint64 || scaled(1000, 128) != 500 {
		t.Fatal("fixed-point scale overflow")
	}
	if marginRate(100000, 256) != 99000 {
		t.Fatal("pacing margin differs from reference")
	}
}
func TestBBRAggregationBudgetAndExpiry(t *testing.T) {
	c := trainedBBR(t, ProbeCruise)
	now := time.Unix(100, 0)
	c.updateACKAggregation(AckEvent{Now: now}, 1000)
	c.updateACKAggregation(AckEvent{Now: now}, 8000)
	if max(c.extra[0], c.extra[1]) != 9000 {
		t.Fatal("ACK compression was not measured")
	}
	c.roundStart = true
	for i := range 10 {
		c.updateACKAggregation(AckEvent{Now: now.Add(time.Duration(i+1) * time.Second)}, 1000)
	}
	if max(c.extra[0], c.extra[1]) > 1000 {
		t.Fatal("stale ACK aggregation did not expire")
	}
}

func TestBBRIdleRestartCompletesExpiredProbeRTT(t *testing.T) {
	c := trainedBBR(t, ProbeCruise)
	now := time.Unix(100, 0)
	c.mode = ProbeRTT
	c.window = 4000
	c.priorWindow = 20000
	c.probeDone = now.Add(-time.Second)
	c.OnPacketSent(SentPacket{Now: now, IdleRestart: true, AppLimited: true, Delivered: 10000})
	if c.mode != ProbeBW || c.phase != ProbeCruise || c.window != 20000 || c.rate != 99000 {
		t.Fatalf("idle restart retained stale probe cap: %+v window=%d pace=%d", c.Snapshot(), c.window, c.rate)
	}
	c.inflightHi = 6000
	if c.headroom() != 5000 {
		t.Fatal("headroom failed to reserve at least one actual packet")
	}
}
