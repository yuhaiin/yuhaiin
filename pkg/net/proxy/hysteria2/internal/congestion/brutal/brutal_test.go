package brutal

import (
	"math"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// Only the smoothed RTT is used when querying Brutal's congestion window.
type fixedRTT struct {
	congestion.RTTStatsProvider
	rtt time.Duration
}

func (f fixedRTT) SmoothedRTT() time.Duration { return f.rtt }

func TestBrutalRateDoesNotOverflow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rate     uint64
		expected congestion.ByteCount
	}{
		{"normal", 65536, 65536},
		{"largest_signed", uint64(math.MaxInt64), congestion.ByteCount(math.MaxInt64)},
		{"above_signed", uint64(math.MaxInt64) + 1, congestion.ByteCount(math.MaxInt64)},
		{"max_unsigned", math.MaxUint64, congestion.ByteCount(math.MaxInt64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewBrutalSender(tc.rate, false)
			if s.bps != tc.expected {
				t.Fatalf("bps = %d, want %d", s.bps, tc.expected)
			}
			if budget := s.pacer.Budget(monotime.Now()); budget <= 0 {
				t.Fatalf("pacing budget = %d", budget)
			}
			s.ackRate = minAckRate
			s.SetRTTStatsProvider(fixedRTT{rtt: 30 * time.Second})
			if cwnd := s.GetCongestionWindow(); cwnd < s.maxDatagramSize {
				t.Fatalf("congestion window overflowed: %d", cwnd)
			}
		})
	}
}
