package lightweight

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"os"
	"time"
)

func (c *TCPConn) schedule(now time.Time) {
	if c.state == Closed {
		c.stack.scheduler.set(&c.job, time.Time{})
		return
	}
	at := earliest(c.endAt, c.ackAt)
	if c.outputWaiting {
		at = c.endAt
	}
	if c.state == SynSent || c.state == SynReceived {
		at = earliest(at, c.born.Add(c.stack.config.HandshakeTimeout))
	}
	if c.state != TimeWait && !c.outputWaiting {
		at = earliest(at, c.rtoAt)
		at = earliest(at, c.persistAt)
		if c.controller.PacingRate() > 0 && c.peerWindow > 0 && c.flight() < c.controller.CongestionWindow() {
			for _, v := range c.tx {
				if v.transmissions == 0 && v.flags&flagSYN == 0 && before(v.seq, c.sndUna+c.peerWindow) {
					at = earliest(at, maxTime(c.paceAt, now))
					break
				}
			}
		}
		if c.stack.config.KeepaliveIdle > 0 && c.state == Established && c.sndUna == c.sndNxt {
			idle := c.stack.config.KeepaliveIdle
			if c.keepaliveSent > 0 {
				idle = c.stack.config.KeepaliveInterval
			}
			at = earliest(at, c.lastActive.Add(idle))
		}
	}
	// Serialize the readiness observation and heap update with writer wakeups.
	// Otherwise a writer can install an immediate job after our observation,
	// only for this stale deadline (possibly zero) to overwrite/remove it.
	c.stack.outputMu.Lock()
	if c.outputReady.Load() {
		at = earliest(at, now)
	}
	c.stack.scheduler.set(&c.job, at)
	c.stack.outputMu.Unlock()
}
func (c *TCPConn) retransmit(now time.Time) {
	for _, v := range c.tx {
		if v.transmissions > 0 && !v.sacked {
			c.transmit(v, now, true)
			return
		}
	}
	// SACK is advisory and a receiver may renege. An RTO still retransmits the
	// oldest cumulatively unacknowledged segment, even if all are SACKed.
}
func (c *TCPConn) onTimer(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == Closed {
		return
	}
	if c.outputReady.Swap(false) {
		c.outputWaiting = false
	}
	if !c.endAt.IsZero() && !now.Before(c.endAt) {
		if c.state == TimeWait {
			c.finish(nil)
		} else {
			c.sendReset()
			c.finish(os.ErrDeadlineExceeded)
		}
		return
	}
	if (c.state == SynSent || c.state == SynReceived) && now.Sub(c.born) >= c.stack.config.HandshakeTimeout {
		c.finish(os.ErrDeadlineExceeded)
		return
	}
	if c.ackPending > 0 && (c.ackAt.IsZero() || !now.Before(c.ackAt)) {
		c.sendACK()
	}
	if !c.rtoAt.IsZero() && !now.Before(c.rtoAt) {
		if c.retries >= 12 {
			c.sendReset()
			c.finish(os.ErrDeadlineExceeded)
			return
		}
		c.retries++
		// Retain a recovery boundary after RTO too. Partial cumulative ACKs
		// must repair the next hole instead of stalling a full old flight for
		// another exponential RTO. The controller still takes its timeout path.
		c.recovering = true
		c.recover = c.sndNxt
		c.dupACKs = 0
		for _, v := range c.tx {
			v.sacked = false
		}
		c.controller.OnTimeout(congestion.TimeoutEvent{Now: now, BytesInFlight: uint64(c.sndNxt - c.sndUna)})
		c.retransmit(now)
		c.rto = min(time.Minute, c.rto*2)
		c.rtoAt = now.Add(c.rto)
	}
	if !c.persistAt.IsZero() && !now.Before(c.persistAt) {
		c.output(c.sndUna-1, flagACK, nil)
		c.persistAt = now.Add(min(time.Minute, c.rto*time.Duration(1<<min(c.persistProbes, 6))))
		c.persistProbes++
		if c.persistProbes > 12 {
			c.finish(os.ErrDeadlineExceeded)
			return
		}
	}
	if c.stack.config.KeepaliveIdle > 0 && c.state == Established && c.sndUna == c.sndNxt {
		idle := c.stack.config.KeepaliveIdle
		if c.keepaliveSent > 0 {
			idle = c.stack.config.KeepaliveInterval
		}
		if now.Sub(c.lastActive) >= idle {
			if c.keepaliveSent >= c.stack.config.KeepaliveProbes {
				c.finish(os.ErrDeadlineExceeded)
				return
			}
			c.output(c.sndUna-1, flagACK, nil)
			c.keepaliveSent++
			c.lastActive = now
		}
	}
	c.pump(now)
}
