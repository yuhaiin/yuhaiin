// SPDX-License-Identifier: BSD-3-Clause
// BBR v3 attribution and license terms are in the repository's licenses/bbr-v3.md.

package congestion

import (
	"math"
	"time"
)

func (c *bbr) bdp(bw, gain uint64) uint64 {
	if c.minRTT == 0 {
		return c.initial
	}
	packets := math.Ceil(float64(bw) * c.minRTT.Seconds() * float64(gain) / 256 / float64(c.config.MSS))
	if packets >= float64(c.config.MaxWindow/c.config.MSS) {
		return c.config.MaxWindow
	}
	return uint64(packets) * c.config.MSS
}

// Quantization covers three actual sender/receiver batches. PacketIO has no
// synthetic TSO allowance: its batching budget comes from the sender's pacing
// quantum and pump limit. This is independent of NIC offload capability.
func (c *bbr) batchBytes() uint64 {
	n := float64(c.rate) * c.config.PacingQuantum.Seconds()
	limit := c.config.MaxBurstPackets * c.config.MSS
	if n >= float64(limit) {
		return limit
	}
	return max(c.config.MSS, uint64(n)/c.config.MSS*c.config.MSS)
}
func (c *bbr) quantize(n uint64) uint64 {
	n = max(n, 3*c.batchBytes(), c.minimum())
	if c.mode == ProbeBW && c.phase == ProbeUp {
		n += 2 * c.config.MSS
	}
	return min(n, c.config.MaxWindow)
}
func (c *bbr) inflight(bw, gain uint64) uint64 { return c.quantize(c.bdp(bw, gain)) }
func (c *bbr) probeWindow() uint64 {
	return min(c.config.MaxWindow, max(c.minimum(), c.bdp(c.bandwidth(), 128)))
}
func (c *bbr) headroom() uint64 {
	if c.inflightHi == bbrUnbounded {
		return bbrUnbounded
	}
	reserve := max(c.config.MSS, scaled(c.inflightHi, 38))
	return max(c.minimum(), c.inflightHi-min(c.inflightHi, reserve))
}
func (c *bbr) inNetwork(e AckEvent, flight uint64) uint64 {
	if c.gain > 256 {
		flight += c.batchBytes()
	}
	delivered := float64(c.bandwidth()) * max(e.PacingDelay, 0).Seconds()
	if delivered >= float64(flight) {
		return 0
	}
	return flight - uint64(delivered)
}
func (c *bbr) setWindow(e AckEvent, fresh uint64) {
	if fresh > 0 {
		extra := max(c.extra[0], c.extra[1])
		extra = min(extra, uint64(float64(c.bandwidth())*.1))
		target := c.quantize(min(c.config.MaxWindow, c.bdp(c.bandwidth(), c.cwndGain)+extra))
		if c.fullReached {
			c.window = min(target, c.window+fresh)
		} else if c.window < target || c.window < 2*c.initial {
			c.window += fresh
		}
		c.window = max(c.window, c.minimum())
	}
	if c.mode == ProbeRTT {
		c.window = min(c.window, c.probeWindow())
	}
	cap := bbrUnbounded
	switch c.mode {
	case ProbeBW:
		if c.phase == ProbeCruise {
			cap = c.headroom()
		} else {
			cap = c.inflightHi
		}
	case ProbeRTT:
		cap = c.headroom()
	}
	cap = max(c.minimum(), min(cap, c.inflightLo))
	c.window = min(c.window, cap, c.config.MaxWindow)
}
func (c *bbr) updateACKAggregation(e AckEvent, fresh uint64) {
	if c.roundStart {
		c.extraRounds++
		rounds := 5
		if !c.fullReached {
			rounds = 1
		}
		if c.extraRounds >= rounds {
			c.extraRounds = 0
			c.extraIndex ^= 1
			c.extra[c.extraIndex] = 0
		}
	}
	expected := uint64(0)
	if !c.ackEpoch.IsZero() {
		n := float64(c.bandwidth()) * max(e.Now.Sub(c.ackEpoch), 0).Seconds()
		if n >= float64(bbrUnbounded) {
			expected = bbrUnbounded
		} else {
			expected = uint64(n)
		}
	}
	if c.ackEpoch.IsZero() || c.ackEpochBytes <= expected || c.ackEpochBytes+fresh >= (1<<20)*c.config.MSS {
		c.ackEpochBytes = 0
		c.ackEpoch = e.Now
		expected = 0
	}
	c.ackEpochBytes += fresh
	excess := c.ackEpochBytes - min(c.ackEpochBytes, expected)
	c.extra[c.extraIndex] = max(c.extra[c.extraIndex], min(excess, c.window))
}
func (c *bbr) adaptLowerBounds() {
	if c.probing() || !c.lossInRound {
		return
	}
	if c.bwLo == bbrUnbounded {
		c.bwLo = c.maxBW()
	}
	if c.inflightLo == bbrUnbounded {
		c.inflightLo = c.window
	}
	c.bwLo = max(1, c.bwLatest, scaled(c.bwLo, 180))
	c.inflightLo = max(c.inflightLatest, scaled(c.inflightLo, 180))
}
func (c *bbr) resetSignals()               { c.lossInRound = false; c.bwLatest = 0; c.inflightLatest = 0 }
func (c *bbr) resetLower()                 { c.bwLo = bbrUnbounded; c.inflightLo = bbrUnbounded }
func (c *bbr) resetFull()                  { c.fullBW = 0; c.fullRounds = 0; c.fullNow = false }
func lossTooHigh(lost, flight uint64) bool { return lost > 0 && flight > 0 && lost > scaled(flight, 5) }
func (c *bbr) updateGains() {
	c.cwndGain = 512
	switch c.mode {
	case Startup:
		c.gain = bbrStartupGain
	case Drain:
		c.gain = 128
	case ProbeBW:
		switch c.phase {
		case ProbeUp:
			c.gain = 320
			c.cwndGain = 576
		case ProbeDown:
			c.gain = 232
		default:
			c.gain = 256
		}
	case ProbeRTT:
		c.gain = 256
		c.cwndGain = 256
	}
}
func (c *bbr) updateMinRTT(e AckEvent) {
	if c.probeStamp.IsZero() {
		c.probeStamp = e.Now
		c.minStamp = e.Now
	}
	expired := e.Now.Sub(c.probeStamp) > 5*time.Second
	if e.RTT > 0 && (c.probeMin == 0 || e.RTT < c.probeMin || expired) {
		c.probeMin = e.RTT
		c.probeStamp = e.Now
	}
	if c.probeMin > 0 && (c.minRTT == 0 || c.probeMin <= c.minRTT || e.Now.Sub(c.minStamp) > 10*time.Second) {
		c.minRTT = c.probeMin
		c.minStamp = c.probeStamp
	}
	if expired && !c.idleRestart && c.mode != ProbeRTT {
		c.priorWindow = max(c.priorWindow, c.window)
		c.mode = ProbeRTT
		c.probeDone = time.Time{}
		c.ackPhase = bbrACKStopping
		c.nextRound = e.Delivered
	}
	if c.mode == ProbeRTT {
		if c.probeDone.IsZero() && e.BytesInFlight <= c.probeWindow() {
			c.probeDone = e.Now.Add(200 * time.Millisecond)
			c.probeRound = c.round
			c.nextRound = e.Delivered
		} else if !c.probeDone.IsZero() && e.Now.After(c.probeDone) && c.round > c.probeRound {
			c.finishProbeRTT(e)
		}
	}
	if e.NewlyDelivered > 0 || e.AckedBytes > 0 {
		c.idleRestart = false
	}
}

func (c *bbr) finishProbeRTT(e AckEvent) {
	c.probeStamp = e.Now
	c.window = max(c.window, c.priorWindow)
	c.resetLower()
	if c.fullReached {
		c.mode = ProbeBW
		c.startDown(e)
		c.phase = ProbeCruise
	} else {
		c.mode = Startup
	}
}
