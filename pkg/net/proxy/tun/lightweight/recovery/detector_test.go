package recovery

import (
	"fmt"
	"testing"
	"time"
)

type testFlight []Segment

func (f testFlight) Len() int         { return len(f) }
func (f testFlight) At(i int) Segment { return f[i] }
func packet(seq uint32, sent time.Time) Segment {
	return Segment{Range: Range{seq, seq + 1000}, Sent: sent, Transmissions: 1, Data: true}
}

func TestRegistry(t *testing.T) {
	if _, err := New("unknown"); err == nil {
		t.Fatal("accepted unknown detector")
	}
	for _, name := range Names() {
		a, err := New(name)
		if err != nil {
			t.Fatal(err)
		}
		b, err := New(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := a.(*rack); ok && a == b {
			t.Fatal("shared connection state")
		}
	}
	if err := Register("", nil); err == nil {
		t.Fatal("accepted invalid factory")
	}
	if err := Register("classic", func() Detector { return &classic{} }); err == nil {
		t.Fatal("overwrote detector")
	}
}

func TestRACKReorderingDeadlineAndSequenceWrap(t *testing.T) {
	for _, seq := range []uint32{100, 0xfffffc00} {
		t.Run(fmt.Sprint(seq), func(t *testing.T) {
			start := time.Unix(100, 0)
			r := &rack{multiplier: 1}
			f := testFlight{packet(seq, start), packet(seq+1000, start.Add(time.Millisecond))}
			f[1].SACKed = true
			r.Delivered(f[1], start.Add(11*time.Millisecond))
			e := Event{Kind: ACK, Now: start.Add(11 * time.Millisecond), Una: seq, Next: seq + 2000, MSS: 1000, SACK: true, HasSACK: true, SRTT: 10 * time.Millisecond}
			d := r.Evaluate(e, f)
			if d.Count != 0 || !d.Next.Equal(start.Add(12500*time.Microsecond)) {
				t.Fatalf("premature loss or bad settling timer: %+v", d)
			}
			e.Kind, e.Now = Timer, d.Next
			d = r.Evaluate(e, f)
			if d.Count != 1 || d.Losses[0] != f[0].Range {
				t.Fatalf("did not repair original hole: %+v", d)
			}
		})
	}
}

func TestRACKIgnoresAmbiguousRetransmissionAndFindsReloss(t *testing.T) {
	start := time.Unix(100, 0)
	r := &rack{multiplier: 1}
	r.Delivered(packet(100, start), start.Add(10*time.Millisecond))
	retrans := packet(1100, start.Add(20*time.Millisecond))
	retrans.Transmissions = 2
	r.Delivered(retrans, start.Add(21*time.Millisecond))
	if !r.latest.Equal(start) {
		t.Fatal("ambiguous retransmission changed delivery clock")
	}
	later := packet(2100, start.Add(21*time.Millisecond))
	later.Transmissions = 2
	later.SACKed = true
	r.Delivered(later, start.Add(31*time.Millisecond))
	f := testFlight{retrans, later}
	d := r.Evaluate(Event{Kind: ACK, Now: start.Add(35 * time.Millisecond), Una: 1100, Next: 3100, MSS: 1000, SACK: true, InRecovery: true, SRTT: 10 * time.Millisecond}, f)
	if d.Count != 1 || d.Losses[0] != retrans.Range {
		t.Fatal("lost retransmission needs fresh chronological evidence")
	}
}

func TestRACKRTOLeavesRecentPacketsInFlight(t *testing.T) {
	start := time.Unix(100, 0)
	r := &rack{multiplier: 1, rtt: 100 * time.Millisecond, minRTT: 100 * time.Millisecond}
	f := testFlight{packet(1, start), packet(1001, start.Add(990*time.Millisecond))}
	d := r.Evaluate(Event{Kind: Timeout, Now: start.Add(time.Second), Una: 1, SACK: true, InRecovery: true, SRTT: 100 * time.Millisecond}, f)
	if d.Count != 1 || d.Losses[0] != f[0].Range {
		t.Fatal("RTO spuriously marked fresh data lost")
	}
}

func TestRACKDSACKAdaptationAndFallback(t *testing.T) {
	start := time.Unix(100, 0)
	r := &rack{multiplier: 1, minRTT: 40 * time.Millisecond}
	e := Event{Kind: ACK, Now: start, Una: 1, Next: 3001, SACK: true, DSACK: true, SRTT: 40 * time.Millisecond}
	r.Evaluate(e, testFlight(nil))
	r.Evaluate(e, testFlight(nil))
	if r.multiplier != 2 || !r.reordered {
		t.Fatal("DSACK adaptation grew more than once per round")
	}
	e.Una = 3001
	e.Next = 6001
	r.Evaluate(e, testFlight(nil))
	if r.multiplier != 3 {
		t.Fatal("new DSACK round did not expand tolerance")
	}
	f := testFlight{packet(1, start)}
	e = Event{Kind: ACK, Now: start, Una: 1, Next: 1001, DupACKs: 3, MSS: 1000}
	if d := r.Evaluate(e, f); d.Count != 1 {
		t.Fatal("SACK-less connection did not fall back")
	}
}

func TestTLPProbesOnceAndRetainsRepairedLossEvidence(t *testing.T) {
	start := time.Unix(100, 0)
	r := &rack{multiplier: 1}
	r.Delivered(packet(1, start), start.Add(10*time.Millisecond))
	f := testFlight{packet(1001, start.Add(20*time.Millisecond)), packet(2001, start.Add(20*time.Millisecond))}
	r.Sent(SentEvent{Segment: f[1], Next: 3001})
	e := Event{Kind: ACK, Now: start.Add(20 * time.Millisecond), Una: 1001, Next: 3001, MSS: 1000, SACK: true, SRTT: 10 * time.Millisecond, RTOAt: start.Add(time.Second), CanProbe: true}
	d := r.Evaluate(e, f)
	if d.Probe || !d.Next.Equal(start.Add(40*time.Millisecond)) {
		t.Fatal("invalid PTO")
	}
	e.Kind, e.Now = Timer, d.Next
	d = r.Evaluate(e, f)
	if !d.Probe || d.Count != 0 {
		t.Fatal("probe was treated as proven loss")
	}
	f[1].Sent, f[1].Transmissions = e.Now, 2
	r.Sent(SentEvent{Segment: f[1], Next: 3001, Probe: true})
	if d = r.Evaluate(e, f); d.Probe || !d.Next.IsZero() {
		t.Fatal("repeated probe without fresh RTT")
	}
	e.Kind, e.Una, e.Next, e.Acked = ACK, 3001, 3001, 2000
	if d = r.Evaluate(e, testFlight(nil)); d.RepairedLoss {
		t.Fatal("exact probe ACK resolved retransmission ambiguity")
	}
	e.Una, e.Next, e.Acked = 4001, 4001, 1000
	if d = r.Evaluate(e, testFlight(nil)); !d.RepairedLoss || d.RepairedBytes != 1000 {
		t.Fatal("lost repaired-probe evidence after flight drained")
	}
}

func TestBoundedLossDecisions(t *testing.T) {
	f := make(testFlight, 100)
	for i := range f {
		f[i] = packet(uint32(1+1000*i), time.Unix(100, 0))
	}
	d := (&classic{}).Evaluate(Event{Kind: Timeout}, f)
	if d.Count != 64 || !d.More {
		t.Fatal("loss decision is not bounded")
	}
}

func BenchmarkDetectorACK(b *testing.B) {
	for _, name := range []string{"classic", "rack-tlp"} {
		for _, count := range []int{16, 256, 4096} {
			b.Run(fmt.Sprintf("%s/flight=%d", name, count), func(b *testing.B) {
				r, err := New(name)
				if err != nil {
					b.Fatal(err)
				}
				start := time.Unix(100, 0)
				f := make(testFlight, count)
				for i := range f {
					f[i] = packet(uint32(i*1000+1), start)
				}
				e := Event{Kind: ACK, Now: start.Add(10 * time.Millisecond), Una: 1, Next: uint32(count*1000 + 1), MSS: 1000, SACK: true, SRTT: 10 * time.Millisecond}
				var view Flight = f
				b.ReportAllocs()
				for b.Loop() {
					_ = r.Evaluate(e, view)
				}
			})
		}
	}
}

func TestRACKPMTURepairNeedsFreshFlightEvidence(t *testing.T) {
	start := time.Unix(100, 0)
	r := &rack{multiplier: 1}
	r.Delivered(packet(1, start), start.Add(10*time.Millisecond))
	repaired := packet(1001, start.Add(20*time.Millisecond))
	repaired.Transmissions = 2
	repaired.RetransmitEnd = 4001
	repaired.PMTURepair = true
	later := packet(2001, start.Add(21*time.Millisecond))
	later.Transmissions = 2
	later.SACKed = true
	r.Delivered(later, start.Add(41*time.Millisecond))
	f := testFlight{repaired, later}
	e := Event{Kind: ACK, Now: start.Add(50 * time.Millisecond), Una: 1001, Next: 4001, MSS: 1000, SACK: true, SRTT: 10 * time.Millisecond}
	if d := r.Evaluate(e, f); d.Count != 0 {
		t.Fatal("old-flight ACK classified PMTU replacement as congestion loss")
	}
	fresh := packet(4001, start.Add(30*time.Millisecond))
	r.Delivered(fresh, start.Add(50*time.Millisecond))
	if d := r.Evaluate(e, f); d.Count != 1 || d.Losses[0] != repaired.Range {
		t.Fatal("new-flight evidence did not detect lost PMTU replacement")
	}
}

func TestPMTUReplacementCancelsPendingTailProbeEvidence(t *testing.T) {
	start := time.Unix(100, 0)
	r := &rack{multiplier: 1}
	r.Delivered(packet(1, start), start.Add(10*time.Millisecond))
	probe := packet(3001, start.Add(20*time.Millisecond))
	probe.Transmissions = 2
	r.Sent(SentEvent{Segment: probe, Next: probe.End, Probe: true})

	// A router rejects the probe at the old MTU. The core resends its range
	// as PMTU replacements before cumulative delivery passes the probe end.
	replacement := probe
	replacement.End = replacement.Start + 500
	replacement.Sent = start.Add(30 * time.Millisecond)
	replacement.Transmissions++
	replacement.PMTURepair = true
	r.Sent(SentEvent{Segment: replacement, Next: 5001})
	e := Event{Kind: ACK, Now: start.Add(50 * time.Millisecond), Una: 5001, Next: 5001,
		Acked: 1000, MSS: 500, SACK: true, SRTT: 10 * time.Millisecond}
	if d := r.Evaluate(e, testFlight{}); d.RepairedLoss || d.RepairedBytes != 0 {
		t.Fatal("PMTU replacement retained congestion-loss evidence from the rejected tail probe")
	}
}
