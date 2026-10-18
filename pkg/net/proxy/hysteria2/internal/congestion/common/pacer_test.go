package common

import (
	"math"
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

func TestSaturatingByteCount(t *testing.T) {
	for _, tt := range []struct {
		value    float64
		expected congestion.ByteCount
	}{
		{0, 0},
		{-1, 0},
		{math.NaN(), 0},
		{math.Inf(1), congestion.ByteCount(math.MaxInt64)},
		{float64(math.MaxInt64), congestion.ByteCount(math.MaxInt64)},
		{1_234.5, 1_234},
	} {
		if got := SaturatingByteCount(tt.value); got != tt.expected {
			t.Fatalf("value=%g got %d want %d", tt.value, got, tt.expected)
		}
	}
}

func TestPacerHugeRateDoesNotOverflow(t *testing.T) {
	p := NewPacer(func() congestion.ByteCount { return congestion.ByteCount(math.MaxInt64) })
	t0 := monotime.Now()
	p.SentPacket(t0, congestion.InitialPacketSize)
	if budget := p.Budget(t0.Add(3 * time.Second)); budget < 0 {
		t.Fatalf("budget overflowed: %d", budget)
	}
	if burst := p.maxBurstSize(); burst < p.maxDatagramSize {
		t.Fatalf("burst overflowed: %d", burst)
	}
}

func TestPacerZeroRateAvoidsDivideByZero(t *testing.T) {
	p := NewPacer(func() congestion.ByteCount { return 0 })
	t0 := monotime.Now()
	p.SentPacket(t0, 10*congestion.InitialPacketSize)
	if p.TimeUntilSend().IsZero() {
		t.Fatal("expected delayed send on zero bandwidth")
	}
}
