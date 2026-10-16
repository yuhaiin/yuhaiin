package congestion

import (
	"math"
	"time"
)

// CUBIC uses byte windows at the interface and segment windows in its cubic
// function. RFC 9406 HyStart++ controls the slow-start exit.
type cubic struct {
	hy                                   hystart
	config                               Config
	window, threshold                    uint64
	lastMax, origin, k, friendly, credit float64
	epoch, idle                          time.Time
	minRTT                               time.Duration
	recovery                             bool
}

func newCubic(c Config) *cubic {
	return &cubic{config: c, window: initialWindow(c), threshold: c.MaxWindow}
}
func (c *cubic) CongestionWindow() uint64 { return c.window }
func (c *cubic) PacingRate() uint64       { return 0 }
func (c *cubic) OnPacketSent(e SentPacket) {
	if e.BytesInFlight == 0 && !c.idle.IsZero() && !c.epoch.IsZero() {
		c.epoch = c.epoch.Add(e.Now.Sub(c.idle))
		c.idle = time.Time{}
	}
}
func (c *cubic) OnAck(e AckEvent) {
	if e.RTT > 0 && (c.minRTT == 0 || e.RTT < c.minRTT) {
		c.minRTT = e.RTT
	}
	if e.BytesInFlight == 0 {
		c.idle = e.Now
	}
	if c.recovery {
		if e.RecoveryDone {
			c.recovery = false
		}
		return
	}
	if e.AckedBytes == 0 || e.AppLimited {
		return
	}
	if c.window < c.threshold {
		growth, exit := c.hy.ack(e, c.config.MSS)
		c.window = min(c.config.MaxWindow, c.window+growth)
		if exit {
			c.threshold = c.window
		}
		return
	}
	w := float64(c.window) / float64(c.config.MSS)
	if c.epoch.IsZero() {
		c.epoch = e.Now
		c.friendly = w
		if w < c.lastMax {
			c.k = math.Cbrt((c.lastMax - w) / 0.4)
			c.origin = c.lastMax
		} else {
			c.k = 0
			c.origin = w
		}
	}
	elapsed := e.Now.Sub(c.epoch).Seconds() + c.minRTT.Seconds()
	delta := elapsed - c.k
	target := 0.4*delta*delta*delta + c.origin
	// Reno-friendly growth with beta=0.7: alpha=3(1-beta)/(1+beta).
	c.friendly += (3 * 0.3 / 1.7) * (float64(e.AckedBytes) / float64(c.config.MSS)) / w
	target = max(target, c.friendly)
	// RFC 9438 bounds the target to at most 1.5*cwnd per RTT.
	target = min(target, 1.5*w)
	if target > w {
		c.credit += (target - w) / w * float64(e.AckedBytes)
		inc := uint64(c.credit)
		c.credit -= float64(inc)
		c.window = min(c.config.MaxWindow, c.window+inc)
	}
}
func (c *cubic) OnLoss(e LossEvent) {
	c.hy.reset()
	w := float64(c.window) / float64(c.config.MSS)
	if w < c.lastMax {
		c.lastMax = w * 0.85
	} else {
		c.lastMax = w
	}
	c.window = max(2*c.config.MSS, uint64(float64(min(c.window, e.BytesInFlight))*0.7))
	c.threshold = c.window
	c.epoch = time.Time{}
	c.credit = 0
	c.recovery = true
}
func (c *cubic) OnTimeout(e TimeoutEvent) {
	c.hy.reset()
	c.OnLoss(LossEvent{Now: e.Now, BytesInFlight: e.BytesInFlight})
	c.window = c.config.MSS
	c.recovery = false
}

func (c *cubic) UpdateMSS(mss uint64) {
	if mss == 0 || mss > 65535 {
		return
	}
	c.config.MSS = mss
	c.window = min(c.config.MaxWindow, max(c.window, mss))
	c.threshold = min(c.config.MaxWindow, max(c.threshold, 2*mss))
}
