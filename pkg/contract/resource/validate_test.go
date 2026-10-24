package resource

import (
	"math"
	"testing"
)

func TestQuotaValidationExactDecimalAndPeriods(t *testing.T) {
	for _, value := range []string{"-1", "+1", "1.5", "1e6", "9223372036854775808", " 1", "１２"} {
		if _, err := ParseBytes(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	if n, err := ParseBytes("9223372036854775807"); err != nil || n != 1<<63-1 {
		t.Fatalf("maximum exact limit: %d %v", n, err)
	}
	valid := Quota{ID: "daily", Period: "daily", Combined: "9007199254740993", Action: "block_new", Thresholds: []int{80, 90, 100}}
	if err := ValidateQuotas([]Quota{valid}); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Quota){
		func(q *Quota) { q.Period = "hourly" }, func(q *Quota) { q.Action = "allow" }, func(q *Quota) { q.ID = "" }, func(q *Quota) { q.Thresholds = []int{80, 80} }, func(q *Quota) { q.Thresholds = []int{101} }, func(q *Quota) { q.Action = "throttle" }, func(q *Quota) { q.Combined = "0" },
	} {
		q := valid
		mutate(&q)
		if err := ValidateQuotas([]Quota{q}); err == nil {
			t.Errorf("accepted invalid quota %+v", q)
		}
	}
	if err := ValidateQuotas([]Quota{valid, valid}); err == nil {
		t.Fatal("duplicate period/ID accepted")
	}
	for _, n := range []float64{-1, math.NaN(), math.Inf(1), 1000001} {
		if err := ValidateLimits(Limits{ConnectionsPerSecond: n}); err == nil {
			t.Error("invalid admission rate")
		}
	}
}

func TestIndividualCompositionIsCommutative(t *testing.T) {
	a := Limits{MaxTCPSessions: 10, MaxSessions: 20, ConnectionsPerSecond: 5, PacketsPerSecond: 100}
	b := Limits{MaxUDPSessions: 7, MaxSessions: 12, ConnectionsPerSecond: 10, ConnectionBurst: 20, PacketsPerSecond: 50, PacketBurst: 10}
	want := Limits{MaxTCPSessions: 10, MaxUDPSessions: 7, MaxSessions: 12, ConnectionsPerSecond: 5, ConnectionBurst: 5, PacketsPerSecond: 50, PacketBurst: 10}
	if got := IntersectLimits(a, b); got != want || got != IntersectLimits(b, a) {
		t.Fatalf("non-deterministic composition: %+v", got)
	}
	pa := Profile{Upload: Rate{BytesPerSecond: 1000}, Download: Rate{BytesPerSecond: 200, BurstBytes: 100}}
	pb := Profile{Upload: Rate{BytesPerSecond: 2000, BurstBytes: 100000}, Download: Rate{BytesPerSecond: 100, BurstBytes: 200}}
	wantProfile := Profile{Upload: Rate{BytesPerSecond: 1000, BurstBytes: 65536}, Download: Rate{BytesPerSecond: 100, BurstBytes: 100}}
	if got := IntersectProfile(pa, pb); got != wantProfile || got != IntersectProfile(pb, pa) {
		t.Fatalf("non-deterministic rates: %+v", got)
	}
}
