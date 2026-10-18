package common

import (
	"math"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	maxBurstPackets               = 10
	maxBurstPacingDelayMultiplier = 4
)

// Pacer implements a token bucket pacing algorithm.
type Pacer struct {
	budgetAtLastSent congestion.ByteCount
	maxDatagramSize  congestion.ByteCount
	lastSentTime     monotime.Time
	getBandwidth     func() congestion.ByteCount // in bytes/s
}

func NewPacer(getBandwidth func() congestion.ByteCount) *Pacer {
	p := &Pacer{
		budgetAtLastSent: maxBurstPackets * congestion.InitialPacketSize,
		maxDatagramSize:  congestion.InitialPacketSize,
		getBandwidth:     getBandwidth,
	}
	return p
}

func (p *Pacer) SentPacket(sendTime monotime.Time, size congestion.ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

// SaturatingByteCount converts a computed pacing rate or congestion window
// without overflowing int64. The float64 representation of MaxInt64 rounds
// up to 2^63, so it must be compared before converting.
func SaturatingByteCount(value float64) congestion.ByteCount {
	switch {
	case math.IsNaN(value) || value <= 0:
		return 0
	case value >= float64(math.MaxInt64):
		return congestion.ByteCount(math.MaxInt64)
	default:
		return congestion.ByteCount(value)
	}
}

func (p *Pacer) Budget(now monotime.Time) congestion.ByteCount {
	maxBudget := p.maxBurstSize()
	if p.lastSentTime.IsZero() {
		return maxBudget
	}
	budget := max(p.budgetAtLastSent, 0)
	if budget >= maxBudget {
		return maxBudget
	}
	elapsed := now.Sub(p.lastSentTime)
	if elapsed <= 0 {
		return budget
	}
	// A signed integer multiplication of nanoseconds and bytes/s can wrap
	// well before the final division. Cap the refill before converting.
	refill := float64(p.getBandwidth()) * elapsed.Seconds()
	if refill >= float64(maxBudget-budget) {
		return maxBudget
	}
	return budget + SaturatingByteCount(refill)
}

func (p *Pacer) maxBurstSize() congestion.ByteCount {
	rate := p.getBandwidth()
	duration := maxBurstPacingDelayMultiplier * congestion.MinPacingDelay
	burst := SaturatingByteCount(float64(duration) * float64(rate) / float64(time.Second))
	return max(burst, maxBurstPackets*p.maxDatagramSize)
}

// TimeUntilSend returns when the next packet should be sent.
// It returns the zero value if a packet can be sent immediately.
func (p *Pacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	rate := p.getBandwidth()
	if rate <= 0 {
		return p.lastSentTime.Add(time.Second)
	}
	bw := uint64(rate)
	// We might need to round up this value.
	// Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
	d := diff / bw
	// this is effectively a math.Ceil, but using only integer math
	if diff%bw > 0 {
		d++
	}
	return p.lastSentTime.Add(max(congestion.MinPacingDelay, time.Duration(d)*time.Nanosecond))
}

func (p *Pacer) SetMaxDatagramSize(s congestion.ByteCount) {
	p.maxDatagramSize = s
}
