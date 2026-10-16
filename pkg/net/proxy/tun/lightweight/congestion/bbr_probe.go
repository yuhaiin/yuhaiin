// SPDX-License-Identifier: BSD-3-Clause
// BBR v3 attribution and license terms are in the repository's licenses/bbr-v3.md.

package congestion

import "time"

func (c *bbr) probing() bool {
	return c.mode == Startup || c.mode == ProbeBW && (c.phase == ProbeRefill || c.phase == ProbeUp)
}
func (c *bbr) startDown(e AckEvent) {
	c.resetSignals()
	c.upCount = bbrUnbounded
	c.roundsSinceProbe = c.random(2)
	c.probeWait = 2*time.Second + time.Duration(c.random(uint64(time.Second)))
	c.cycleStamp = e.Now
	c.ackPhase = bbrACKStopping
	c.nextRound = e.Delivered
	c.phase = ProbeDown
}
func (c *bbr) startRefill(e AckEvent) {
	c.resetLower()
	c.upRounds = 0
	c.upACKs = 0
	c.stoppedRisk = false
	c.ackPhase = bbrACKRefilling
	c.nextRound = e.Delivered
	c.phase = ProbeRefill
}
func (c *bbr) raiseSlope() {
	c.upCount = max(1, c.window/(uint64(1)<<c.upRounds)/c.config.MSS) * c.config.MSS
	c.upRounds = min(c.upRounds+1, 30)
}
func (c *bbr) startUp(e AckEvent) {
	c.ackPhase = bbrACKStarting
	c.nextRound = e.Delivered
	c.cycleStamp = e.Now
	c.resetFull()
	c.fullBW = e.DeliveryRate
	c.phase = ProbeUp
	c.raiseSlope()
}
func (c *bbr) tooHigh(e AckEvent) {
	c.prevTooHigh = true
	c.probeSamples = false
	if !e.AppLimited {
		c.inflightHi = max(e.TxInFlight, scaled(min(c.inflight(c.bandwidth(), 256), c.window), 180))
	}
	if c.mode == ProbeBW && c.phase == ProbeUp {
		c.undoMode = 2
		c.startDown(e)
	}
}
func (c *bbr) adaptUpper(e AckEvent, fresh uint64) bool {
	if c.ackPhase == bbrACKStarting && c.roundStart {
		c.ackPhase = bbrACKFeedback
	}
	if c.ackPhase == bbrACKStopping && c.roundStart {
		c.probeSamples = false
		c.ackPhase = bbrACKInit
		if c.mode == ProbeBW && !e.AppLimited && c.bwHi[1] > 0 {
			c.bwHi[0] = c.bwHi[1]
			c.bwHi[1] = 0
		}
		if c.mode == ProbeBW && c.stoppedRisk && !c.prevTooHigh {
			c.startRefill(e)
			return true
		}
	}
	if lossTooHigh(e.SampleLost, e.TxInFlight) {
		if c.probeSamples {
			c.tooHigh(e)
		}
	} else if c.inflightHi != bbrUnbounded {
		c.inflightHi = max(c.inflightHi, e.TxInFlight)
		if c.mode == ProbeBW && c.phase == ProbeUp && e.CwndLimited && c.window >= c.inflightHi {
			c.upACKs += fresh
			if c.upACKs >= c.upCount {
				growth := c.upACKs / c.upCount
				c.upACKs %= c.upCount
				c.inflightHi = min(c.config.MaxWindow, c.inflightHi+growth*c.config.MSS)
			}
			if c.roundStart {
				c.raiseSlope()
			}
		}
	}
	return false
}
func (c *bbr) timeToProbe(e AckEvent) bool {
	rounds := min(uint64(63), max(1, min(c.inflight(c.bandwidth(), 256), c.window)/c.config.MSS))
	if e.Now.Sub(c.cycleStamp) > c.probeWait || c.roundsSinceProbe >= rounds {
		c.startRefill(e)
		return true
	}
	return false
}
func (c *bbr) updateCycle(e AckEvent, fresh uint64) {
	if c.adaptUpper(e, fresh) || c.mode != ProbeBW {
		return
	}
	flight := c.inNetwork(e, e.PriorInFlight)
	switch c.phase {
	case ProbeCruise:
		c.timeToProbe(e)
	case ProbeRefill:
		if c.roundStart {
			c.probeSamples = true
			c.startUp(e)
		}
	case ProbeUp:
		done := false
		if c.prevTooHigh && flight >= c.inflightHi {
			c.stoppedRisk = true
			done = true
		} else if e.CwndLimited && c.window >= c.inflightHi {
			c.resetFull()
			c.fullBW = e.DeliveryRate
		} else if c.fullNow {
			done = true
		}
		if done {
			c.prevTooHigh = false
			c.startDown(e)
		}
	case ProbeDown:
		if c.timeToProbe(e) {
			return
		}
		if flight <= c.headroom() && flight <= c.inflight(c.maxBW(), 256) {
			c.inflightLo = min(c.inflightLo, c.inflightHi)
			c.phase = ProbeCruise
		}
	}
}
