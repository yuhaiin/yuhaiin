package lightweight

import (
	"os"
	"slices"
	"sort"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
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
		for _, v := range c.tx.values() {
			if v.resend {
				at = earliest(at, maxTime(c.paceAt, now))
				break
			}
		}
		at = earliest(at, c.rtoAt)
		at = earliest(at, c.persistAt)
		if c.controller.PacingRate() > 0 && c.peerWindow > 0 && c.flight() < c.controller.CongestionWindow() {
			for _, v := range c.tx.values() {
				if (v.transmissions == 0 || v.lossReported) && v.flags&flagSYN == 0 && before(v.seq, c.sndUna+c.peerWindow) {
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
func (c *TCPConn) markLost(v *sendSegment, now time.Time) bool {
	if v.lossReported || v.transmissions == 0 {
		return false
	}
	v.lossReported = true
	if !v.sacked {
		c.bytesInFlight -= uint64(v.length())
	}
	c.lost += uint64(v.length())
	if observer, ok := c.controller.(congestion.LossSampler); ok {
		observer.OnPacketLost(congestion.LossEvent{Now: now, BytesInFlight: c.flight(), LostBytes: uint64(v.length()), Delivered: c.delivered, SampleLost: c.lost - v.lostAtSend, TxInFlight: v.txInFlight, AppLimited: v.appLimited})
	}
	return true
}

// Three MSS of selectively acknowledged data above an original transmission
// demonstrate a hole. Retransmissions need new evidence (or an RTO), so an old
// repeated SACK block cannot repeatedly mark the replacement as lost.
func (c *TCPConn) inferSACKLoss(now time.Time) bool {
	above := uint64(0)
	changed := false
	values := c.sentSegments()
	for _, v := range slices.Backward(values) {
		if v.transmissions == 0 {
			continue
		}
		if v.sacked {
			above += uint64(v.length())
			continue
		}
		if v.resend {
			continue
		} // An explicit PMTU replacement is already pending.
		evidence := above
		if v.transmissions > 1 {
			// Old duplicate ACKs can describe the flight preceding a PMTU repair.
			// A replacement needs SACK evidence from new sequence space sent after it.
			evidence = 0
			start := sort.Search(len(values), func(j int) bool { return !before(values[j].seq, v.retransmitEnd) })
			for _, later := range values[start:] {
				if later.sacked {
					evidence += uint64(later.length())
				}
				if evidence >= 3*uint64(c.mss) {
					break
				}
			}
		}
		if evidence >= 3*uint64(c.mss) {
			changed = c.markLost(v, now) || changed
		}
	}
	return changed
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
				c.recovering = true
				c.recover = c.sndNxt
				c.controller.OnLoss(congestion.LossEvent{Now: now, BytesInFlight: uint64(c.sndNxt - c.sndUna), LostBytes: uint64(c.mss)})
			}
			for _, v := range c.sentSegments() {
				c.setSACK(v, false)
				c.markLost(v, now)
			}
		}
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
		c.controller.OnTimeout(congestion.TimeoutEvent{Now: now, BytesInFlight: uint64(c.sndNxt - c.sndUna)})
		// Keep useful SACK evidence across an RTO. If the oldest outstanding data
		// was reneged, retry that head. Advancing ACKs that still stop at SACKed
		// data use the separate grace check above.
		for i, v := range c.tx.values() {
			if i == 0 && v.sacked {
				c.setSACK(v, false)
			}
			if v.transmissions > 0 && !v.sacked {
				c.markLost(v, now)
			}
		}
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
