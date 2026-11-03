package lightweight

import (
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/recovery"
)

func (c *TCPConn) schedule(now time.Time) {
	if c.state == Closed {
		c.stack.scheduler.set(&c.job, time.Time{})
		return
	}
	at := earliest(earliest(c.endAt, c.ackAt), c.renegeAt)
	if c.outputWaiting {
		at = c.endAt
	}
	if c.readWaiting {
		at = earliest(at, c.readDeadline)
	}
	if c.writeWaiting {
		at = earliest(at, c.writeDeadline)
	}
	if c.state == SynSent || c.state == SynReceived {
		at = earliest(at, c.born.Add(c.stack.config.HandshakeTimeout))
	}
	if c.state != TimeWait && !c.outputWaiting {
		i := c.nextSendIndex()
		if i < c.tx.len() {
			v := c.tx.values()[i]
			if v.resend {
				at = earliest(at, maxTime(c.paceAt, now))
			}
			if c.controller.PacingRate() > 0 && c.peerWindow > 0 && c.flight() < c.controller.CongestionWindow() && v.flags&flagSYN == 0 && before(v.seq, c.sndUna+c.peerWindow) {
				at = earliest(at, maxTime(c.paceAt, now))
			}
		}
		if c.peerWindow > 0 || c.state == SynSent || c.state == SynReceived {
			at = earliest(at, c.rtoAt)
			at = earliest(at, c.detectorAt)
		}
		at = earliest(at, c.persistAt)
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
func (c *TCPConn) markLost(v *sendSegment, now time.Time) bool {
	if v.lossReported || v.transmissions == 0 {
		return false
	}
	if c.undoValid {
		if v.transmissions != 1 || c.undoCount == len(c.undoRanges) {
			c.undoValid = false
		} else {
			c.undoRanges[c.undoCount] = sackBlock{v.seq, v.seq + v.length()}
			c.undoCount++
		}
	}
	v.pmtuRepair = false
	v.lossReported = true
	c.repairPending = true
	if !v.sacked {
		c.bytesInFlight -= uint64(v.length())
	}
	c.lost += uint64(v.length())
	if observer, ok := c.controller.(congestion.LossSampler); ok {
		observer.OnPacketLost(congestion.LossEvent{Now: now, BytesInFlight: c.flight(), LostBytes: uint64(v.length()), Delivered: c.delivered, SampleLost: c.lost - v.lostAtSend, TxInFlight: v.txInFlight, AppLimited: v.appLimited})
	}
	return true
}

func (c *TCPConn) retransmit(now time.Time) {
	for _, v := range c.sentSegments() {
		if v.lossReported && !v.sacked {
			c.transmit(v, now, true)
			return
		}
	}
	for _, v := range c.tx.values() {
		if v.transmissions > 0 && !v.sacked {
			c.markLost(v, now)
			c.transmit(v, now, true)
			return
		}
	}
}
func (c *TCPConn) onTimer(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == Closed {
		return
	}
	if !c.readDeadline.IsZero() && !now.Before(c.readDeadline) {
		c.notifyRead()
	}
	if !c.writeDeadline.IsZero() && !now.Before(c.writeDeadline) {
		c.notifyWrite()
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
	if !c.renegeAt.IsZero() && !now.Before(c.renegeAt) {
		c.renegeAt = time.Time{}
		if c.tx.len() > 0 && c.tx.values()[0].sacked {
			if !c.recovering {
				c.beginRecovery(now)
			}
			c.undoValid = false
			for _, v := range c.sentSegments() {
				c.setSACK(v, false)
			}
			c.detectLoss(recovery.Reneging, now, 0, false, nil, false)
		}
	}
	if !c.detectorAt.IsZero() && !now.Before(c.detectorAt) && c.peerWindow > 0 {
		if c.detectLoss(recovery.Timer, now, 0, false, nil, false) {
			c.retransmit(now)
		}
	}
	if !c.rtoAt.IsZero() && !now.Before(c.rtoAt) && (c.peerWindow > 0 || c.state == SynSent || c.state == SynReceived) {
		if c.retries >= 12 {
			c.sendReset()
			c.finish(os.ErrDeadlineExceeded)
			return
		}
		c.retries++
		c.undoValid = false
		// Retain a recovery boundary after RTO too. Partial cumulative ACKs
		// must repair the next hole instead of stalling a full old flight for
		// another exponential RTO. The controller still takes its timeout path.
		c.recovering = true
		c.recover = c.sndNxt
		c.dupACKs = 0
		c.controller.OnTimeout(congestion.TimeoutEvent{Now: now, BytesInFlight: uint64(c.sndNxt - c.sndUna)})
		// Keep useful SACK evidence across an RTO. If the oldest outstanding data
		// was reneged, retry that head. Advancing ACKs that still stop at SACKed
		// data use the separate grace check above.
		if c.tx.len() > 0 && c.tx.values()[0].sacked {
			c.setSACK(c.tx.values()[0], false)
		}
		c.detectLoss(recovery.Timeout, now, 0, false, nil, false)
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
