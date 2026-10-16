package congestion

type reno struct {
	config                    Config
	window, threshold, credit uint64
	recovery                  bool
}

func newReno(c Config) *reno {
	return &reno{config: c, window: initialWindow(c), threshold: c.MaxWindow}
}
func (c *reno) OnPacketSent(SentPacket)  {}
func (c *reno) CongestionWindow() uint64 { return c.window }
func (c *reno) PacingRate() uint64       { return 0 }
func (c *reno) OnAck(e AckEvent) {
	if c.recovery {
		if e.RecoveryDone {
			c.window = c.threshold
			c.recovery = false
		} else if e.AckedBytes == 0 {
			c.window = min(c.config.MaxWindow, c.window+c.config.MSS)
		} else {
			c.window = max(c.threshold+c.config.MSS, c.window-min(c.window, e.AckedBytes)+c.config.MSS)
		}
		return
	}
	if e.AckedBytes == 0 {
		return
	}
	if c.window < c.threshold {
		c.window += min(e.AckedBytes, c.config.MSS)
	} else {
		c.credit += e.AckedBytes * c.config.MSS
		grow := c.credit / c.window
		c.credit %= c.window
		c.window += grow
	}
	c.window = min(c.window, c.config.MaxWindow)
}
func (c *reno) OnLoss(e LossEvent) {
	c.threshold = max(2*c.config.MSS, e.BytesInFlight/2)
	c.window = min(c.config.MaxWindow, c.threshold+3*c.config.MSS)
	c.credit = 0
	c.recovery = true
}
func (c *reno) OnTimeout(e TimeoutEvent) {
	c.threshold = max(2*c.config.MSS, e.BytesInFlight/2)
	c.window = c.config.MSS
	c.credit = 0
	c.recovery = false
}
