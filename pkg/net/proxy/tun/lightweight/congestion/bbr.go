// SPDX-License-Identifier: BSD-3-Clause
// BBR v3 attribution and license terms are in the repository's licenses/bbr-v3.md.

package congestion

import (
	"math"
	"math/bits"
	"math/rand/v2"
	"time"
)

// BBR v3 follows google/bbr's bbr-v3-2026-09-16-01 release (674859761ded),
// net/ipv4/tcp_bbr3.c. Units here are bytes and bytes/second, not Linux packets
// and fixed-point packets/microsecond. See bbr_model.go and bbr_probe.go.
type BBRMode string

const (
	Startup  BBRMode = "STARTUP"
	Drain    BBRMode = "DRAIN"
	ProbeBW  BBRMode = "PROBE_BW"
	ProbeRTT BBRMode = "PROBE_RTT"
)

type BBRPhase string

const (
	ProbeUp     BBRPhase = "UP"
	ProbeDown   BBRPhase = "DOWN"
	ProbeCruise BBRPhase = "CRUISE"
	ProbeRefill BBRPhase = "REFILL"
)

type bbrACKPhase uint8

const (
	bbrACKInit bbrACKPhase = iota
	bbrACKRefilling
	bbrACKStarting
	bbrACKFeedback
	bbrACKStopping
)
const (
	bbrUnbounded   = uint64(math.MaxUint64)
	bbrStartupGain = 710 // floor(256*2.77)+1, release's 4*ln(2) approximation.
)

type BBRSnapshot struct {
	Version                                                      int
	Mode                                                         BBRMode
	Phase                                                        BBRPhase
	Bandwidth, MaxBandwidth, BandwidthLo, InflightLo, InflightHi uint64
	MinRTT                                                       time.Duration
	PacingGain                                                   float64
	Round                                                        uint64
	ProbeWait                                                    time.Duration
}
type bbr struct {
	config                                   Config
	mode                                     BBRMode
	phase                                    BBRPhase
	ackPhase                                 bbrACKPhase
	window, initial, priorWindow, rate       uint64
	bwHi                                     [2]uint64
	bwLo, inflightLo, inflightHi             uint64
	bwLatest, inflightLatest                 uint64
	round, nextRound, lossRoundDelivered     uint64
	roundStart, lossRoundStart, lossInRound  bool
	lossEvents                               int
	fullReached, fullNow                     bool
	fullBW                                   uint64
	fullRounds, drainRounds                  int
	gain, cwndGain                           uint64
	minRTT, probeMin                         time.Duration
	minStamp, probeStamp, probeDone          time.Time
	probeRound                               uint64
	idleRestart, seenRTT                     bool
	cycleStamp                               time.Time
	probeWait                                time.Duration
	roundsSinceProbe                         uint64
	probeSamples, prevTooHigh, stoppedRisk   bool
	upRounds                                 uint
	upCount, upACKs                          uint64
	extra                                    [2]uint64
	extraIndex, extraRounds                  int
	ackEpoch                                 time.Time
	ackEpochBytes                            uint64
	recovery, timeoutRecovery                bool
	undoBWLo, undoInflightLo, undoInflightHi uint64
	undoMode                                 uint8
	random                                   func(uint64) uint64
}

func newBBR(c Config) *bbr {
	x := &bbr{config: c, mode: Startup, window: initialWindow(c), initial: initialWindow(c), bwLo: bbrUnbounded, inflightLo: bbrUnbounded, inflightHi: bbrUnbounded, upCount: bbrUnbounded, lossRoundDelivered: 1, random: rand.Uint64N}
	x.updateGains()
	x.rate = max(1, uint64(float64(x.window)/c.InitialRTT.Seconds()*float64(x.gain)/256*.99))
	return x
}
func (c *bbr) CongestionWindow() uint64 { return c.window }
func (c *bbr) PacingRate() uint64       { return max(c.rate, 1) }
func (c *bbr) maxBW() uint64            { return max(c.bwHi[0], c.bwHi[1]) }
func (c *bbr) bandwidth() uint64        { return min(c.maxBW(), c.bwLo) }
func (c *bbr) Snapshot() BBRSnapshot {
	return BBRSnapshot{Version: 3, Mode: c.mode, Phase: c.phase, Bandwidth: c.bandwidth(), MaxBandwidth: c.maxBW(), BandwidthLo: c.bwLo, InflightLo: c.inflightLo, InflightHi: c.inflightHi, MinRTT: c.minRTT, PacingGain: float64(c.gain) / 256, Round: c.round, ProbeWait: c.probeWait}
}

// scaled uses a 128-bit product so adversarial event values cannot wrap a
// bandwidth or inflight bound. Gains have the reference's 8 fractional bits.
func scaled(v, gain uint64) uint64 {
	return mulDiv(v, gain, 256)
}
func mulDiv(v, gain, denominator uint64) uint64 {
	hi, lo := bits.Mul64(v, gain)
	if hi >= denominator {
		return bbrUnbounded
	}
	q, _ := bits.Div64(hi, lo, denominator)
	return q
}
func marginRate(bw, gain uint64) uint64 {
	v := scaled(bw, gain)
	return v/100*99 + v%100*99/100
}
func (c *bbr) RateSampleLimited() bool { return c.mode == ProbeRTT }
func (c *bbr) minimum() uint64         { return min(c.config.MaxWindow, 4*c.config.MSS) }
func (c *bbr) OnPacketSent(e SentPacket) {
	if c.probeStamp.IsZero() {
		c.probeStamp = e.Now
		c.minStamp = e.Now
	}
	if e.IdleRestart && e.AppLimited {
		c.idleRestart = true
		c.ackEpoch = e.Now
		c.ackEpochBytes = 0
		if c.mode == ProbeRTT && !c.probeDone.IsZero() && e.Now.After(c.probeDone) {
			c.finishProbeRTT(AckEvent{Now: e.Now, Delivered: e.Delivered})
			c.updateGains()
		}
		if c.mode == ProbeBW {
			c.rate = max(1, marginRate(c.bandwidth(), 256))
		}
	}
}
func (c *bbr) OnAck(e AckEvent) {
	valid := e.DeliveryRate > 0
	fresh := e.NewlyDelivered
	// Retain compatibility with callers supplying the original controller event
	// shape; real TCP explicitly supplies RateSample and fresh SACK delivery.
	if valid && !e.RateSample && fresh == 0 {
		fresh = e.AckedBytes
	}
	c.roundStart = valid && e.PriorDelivered >= c.nextRound
	if c.roundStart {
		c.round++
		c.nextRound = e.Delivered
		c.roundsSinceProbe = min(c.roundsSinceProbe+1, 255)
	}
	c.lossRoundStart = false
	if valid && fresh > 0 {
		c.bwLatest = max(c.bwLatest, e.DeliveryRate)
		c.inflightLatest = max(c.inflightLatest, e.SampleDelivered)
		if e.PriorDelivered >= c.lossRoundDelivered {
			c.lossRoundDelivered = e.Delivered
			c.lossRoundStart = true
		}
		if !e.AppLimited || e.DeliveryRate >= c.maxBW() {
			c.bwHi[1] = max(c.bwHi[1], e.DeliveryRate)
		}
		c.lossInRound = c.lossInRound || e.LostBytes > 0
		if c.lossRoundStart {
			c.adaptLowerBounds()
			c.lossInRound = false
		}
		c.updateACKAggregation(e, fresh)
	}
	if e.LostBytes > 0 {
		c.lossEvents = min(c.lossEvents+1, 15)
	}
	if !c.fullReached && c.lossRoundStart && e.InRecovery && c.lossEvents >= 6 && lossTooHigh(e.SampleLost, e.TxInFlight) {
		c.fullReached = true
		c.undoMode = 1
		c.inflightHi = max(c.inflight(c.maxBW(), 256), c.inflightLatest)
	}
	if c.lossRoundStart {
		c.lossEvents = 0
	}
	if valid && !e.AppLimited && !c.fullNow {
		if e.DeliveryRate >= scaled(c.fullBW, 320) {
			c.resetFull()
			c.fullBW = e.DeliveryRate
		} else if c.roundStart {
			c.fullRounds++
			c.fullNow = c.fullRounds >= 3
			c.fullReached = c.fullReached || c.fullNow
		}
	}
	if c.mode == Startup && c.fullReached {
		c.mode = Drain
		c.drainRounds = 0
		c.resetSignals()
	}
	if c.mode == Drain {
		if c.roundStart {
			c.drainRounds++
		}
		if c.inNetwork(e, e.BytesInFlight) <= c.inflight(c.maxBW(), 256) || c.drainRounds > 3 {
			c.mode = ProbeBW
			c.startDown(e)
		}
	}
	if c.fullReached {
		c.updateCycle(e, fresh)
	}
	c.updateMinRTT(e)
	if e.RecoveryDone && c.recovery {
		if c.timeoutRecovery {
			c.window = max(c.window, c.priorWindow)
		}
		c.recovery = false
		c.timeoutRecovery = false
	}
	c.updateGains()
	if !c.seenRTT && e.RTT > 0 {
		c.rate = max(1, uint64(float64(c.initial)/e.RTT.Seconds()*float64(bbrStartupGain)/256*.99))
		c.seenRTT = true
	}
	if c.bandwidth() > 0 {
		candidate := max(1, marginRate(c.bandwidth(), c.gain))
		if c.fullReached || candidate > c.rate {
			c.rate = candidate
		}
	}
	c.setWindow(e, fresh)
	if c.lossRoundStart {
		c.bwLatest = e.DeliveryRate
		c.inflightLatest = e.SampleDelivered
	}
}
func (c *bbr) saveRecovery() {
	if !c.recovery {
		c.priorWindow = c.window
		c.undoBWLo = c.bwLo
		c.undoInflightLo = c.inflightLo
		c.undoInflightHi = c.inflightHi
		c.undoMode = 0
	}
	c.recovery = true
}
func (c *bbr) OnLoss(LossEvent) { c.saveRecovery() }
func (c *bbr) OnTimeout(TimeoutEvent) {
	c.saveRecovery()
	c.timeoutRecovery = true
	c.resetFull()
	if !c.probing() && c.inflightLo == bbrUnbounded {
		c.inflightLo = max(c.window, c.priorWindow)
	}
	c.window = c.config.MSS
}
func (c *bbr) OnPacketLost(e LossEvent) {
	c.saveRecovery()
	if !c.lossInRound {
		c.lossRoundDelivered = e.Delivered
	}
	c.lossInRound = true
	if c.probeSamples && lossTooHigh(e.SampleLost, e.TxInFlight) {
		// Find the prefix of this lost packet at which the flight's loss budget
		// was exhausted, rather than setting hi to the entire oversized flight.
		priorFlight := e.TxInFlight - min(e.TxInFlight, e.LostBytes)
		priorLost := e.SampleLost - min(e.SampleLost, e.LostBytes)
		budget := scaled(priorFlight, 5)
		if priorFlight%256*5%256 != 0 {
			budget++
		}
		prefix := budget - min(budget, priorLost)
		prefix = mulDiv(prefix, 256, 251)
		c.tooHigh(AckEvent{Now: e.Now, Delivered: e.Delivered, TxInFlight: priorFlight + prefix, AppLimited: e.AppLimited})
	}
}
func (c *bbr) UpdateMSS(mss uint64) {
	if mss == 0 || mss > 65535 {
		return
	}
	c.config.MSS = mss
	c.window = min(c.config.MaxWindow, max(c.window, mss))
}

// OnSpuriousLoss restores model bounds if the transport can prove that a
// recovery episode was spurious. Merely receiving a delayed ACK is not proof.
func (c *bbr) OnSpuriousLoss(e AckEvent) {
	c.resetFull()
	c.lossInRound = false
	c.lossEvents = 0
	c.lossRoundDelivered = e.Delivered
	c.bwLo = max(c.bwLo, c.undoBWLo)
	c.inflightLo = max(c.inflightLo, c.undoInflightLo)
	c.inflightHi = max(c.inflightHi, c.undoInflightHi)
	if c.undoMode == 1 {
		c.fullReached = false
		if c.mode != ProbeRTT {
			c.mode = Startup
		}
	} else if c.undoMode == 2 && c.mode != ProbeRTT {
		c.mode = ProbeBW
		c.startRefill(e)
	}
	c.undoMode = 0
	c.recovery = false
	c.timeoutRecovery = false
	c.window = max(c.window, c.priorWindow)
	c.updateGains()
	c.setWindow(e, 0)
}
