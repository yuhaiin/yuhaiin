package congestion

import "time"

type BBRMode string

const (
	Startup  BBRMode = "STARTUP"
	Drain    BBRMode = "DRAIN"
	ProbeBW  BBRMode = "PROBE_BW"
	ProbeRTT BBRMode = "PROBE_RTT"
)

type BBRSnapshot struct {
	Mode       BBRMode
	Bandwidth  uint64
	MinRTT     time.Duration
	PacingGain float64
	Round      uint64
}
type bbr struct {
	config                                                  Config
	window, priorWindow, rate, bw, round, nextRound, fullBW uint64
	samples                                                 [10]uint64
	fullRounds, cycle                                       int
	mode                                                    BBRMode
	gain                                                    float64
	minRTT                                                  time.Duration
	minStamp, cycleStamp, probeDone                         time.Time
	probeRound                                              uint64
}

func newBBR(c Config) *bbr {
	x := &bbr{config: c, window: initialWindow(c), mode: Startup, gain: 2.885}
	x.rate = uint64(float64(x.window) / c.InitialRTT.Seconds() * x.gain)
	return x
}
func (c *bbr) CongestionWindow() uint64 { return c.window }
func (c *bbr) PacingRate() uint64       { return max(c.rate, 1) }
func (c *bbr) Snapshot() BBRSnapshot {
	return BBRSnapshot{Mode: c.mode, Bandwidth: c.bw, MinRTT: c.minRTT, PacingGain: c.gain, Round: c.round}
}
func (c *bbr) OnPacketSent(SentPacket) {}
func (c *bbr) bdp() uint64 {
	rtt := c.minRTT
	if rtt == 0 {
		rtt = c.config.InitialRTT
	}
	return max(c.config.MSS, uint64(float64(c.bw)*rtt.Seconds()))
}
func (c *bbr) OnAck(e AckEvent) {
	if e.AckedBytes == 0 {
		return
	}
	newRound := e.PriorDelivered >= c.nextRound
	if newRound {
		c.round++
		c.nextRound = e.Delivered
		c.samples[c.round%10] = 0
	}
	if !e.AppLimited || e.DeliveryRate >= c.bw {
		c.samples[c.round%10] = max(c.samples[c.round%10], e.DeliveryRate)
	}
	c.bw = 0
	for _, s := range c.samples {
		c.bw = max(c.bw, s)
	}
	expired := !c.minStamp.IsZero() && e.Now.Sub(c.minStamp) >= 10*time.Second
	if e.RTT > 0 && (c.minRTT == 0 || e.RTT <= c.minRTT || expired) {
		c.minRTT = e.RTT
		c.minStamp = e.Now
	}
	if expired && c.mode != ProbeRTT && !e.AppLimited {
		c.priorWindow = c.window
		c.mode = ProbeRTT
		c.gain = 1
		c.probeDone = time.Time{}
	}
	switch c.mode {
	case Startup:
		if newRound && !e.AppLimited {
			if c.bw >= c.fullBW+c.fullBW/4 {
				c.fullBW = c.bw
				c.fullRounds = 0
			} else {
				c.fullRounds++
			}
			if c.fullRounds >= 3 {
				c.mode = Drain
				c.gain = 1 / 2.885
			}
		}
	case Drain:
		if e.BytesInFlight <= c.bdp() {
			c.mode = ProbeBW
			c.cycle = 0
			c.gain = 1.25
			c.cycleStamp = e.Now
		}
	case ProbeBW:
		gains := [8]float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}
		if e.Now.Sub(c.cycleStamp) >= c.minRTT && (c.gain <= 1 || e.BytesInFlight >= uint64(float64(c.bdp())*c.gain)) {
			c.cycle = (c.cycle + 1) % len(gains)
			c.gain = gains[c.cycle]
			c.cycleStamp = e.Now
		}
	case ProbeRTT:
		if e.BytesInFlight <= 4*c.config.MSS && c.probeDone.IsZero() {
			c.probeDone = e.Now.Add(200 * time.Millisecond)
			c.probeRound = c.round
		}
		if !c.probeDone.IsZero() && !e.Now.Before(c.probeDone) && c.round > c.probeRound {
			c.minStamp = e.Now
			c.mode = ProbeBW
			c.cycle = 0
			c.gain = 1.25
			c.cycleStamp = e.Now
			c.window = max(c.window, c.priorWindow)
		}
	}
	if c.bw > 0 {
		candidate := uint64(float64(c.bw) * c.gain)
		if c.mode != Startup || candidate > c.rate {
			c.rate = max(candidate, 1)
		}
	}
	target := min(c.config.MaxWindow, max(4*c.config.MSS, 2*c.bdp()+3*c.config.MSS))
	switch c.mode {
	case ProbeRTT:
		c.window = 4 * c.config.MSS
	case Startup:
		c.window = min(c.config.MaxWindow, c.window+e.AckedBytes)
	default:
		c.window = min(target, c.window+e.AckedBytes)
	}
}
func (c *bbr) OnLoss(e LossEvent) {
	c.window = max(4*c.config.MSS, c.window-min(c.window, e.LostBytes))
}
func (c *bbr) OnTimeout(TimeoutEvent) { c.window = 4 * c.config.MSS }
