package lightweight

import (
	"slices"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/recovery"
)

// recoveryFlight borrows the transport's descriptors under the connection lock.
// No send buffers or mutable descriptors cross the detector interface.
type recoveryFlight TCPConn

func (f *recoveryFlight) Len() int { return len((*TCPConn)(f).sentSegments()) }
func (f *recoveryFlight) At(i int) recovery.Segment {
	return recoverySegment((*TCPConn)(f).tx.values()[i])
}
func recoverySegment(v *sendSegment) recovery.Segment {
	return recovery.Segment{Start: v.seq, End: v.seq + v.length(), Sent: v.sent,
		Transmissions: v.transmissions, RetransmitEnd: v.retransmitEnd, SACKed: v.sacked,
		Lost: v.lossReported, Repair: v.resend, Data: len(v.data) > 0, PMTURepair: v.pmtuRepair}
}

func (c *TCPConn) creditDelivery(sample *deliverySample, v *sendSegment, n uint32, now time.Time) {
	if n > v.deliveredBytes {
		s := recoverySegment(v)
		s.End = s.Start + n
		c.detector.Delivered(s, now)
	}
	sample.credit(v, n)
}

func (c *TCPConn) detectLoss(kind recovery.Kind, now time.Time, acked uint64, hasSACK bool, dsack *sackBlock, duplicateACK bool) bool {
	if c.detector == nil {
		return false
	}
	e := recovery.Event{Kind: kind, Now: now, Una: c.sndUna, Next: c.sndNxt, MSS: uint32(c.mss),
		Acked: acked, SRTT: c.srtt, RTOAt: c.rtoAt, SACK: c.sack,
		InRecovery: c.recovering, RecoveryDone: c.recovering && !before(c.sndUna, c.recover), HasSACK: hasSACK,
		CanProbe: (c.state == Established || c.state == CloseWait) && c.peerWindow > 0 && !c.outputWaiting}
	if duplicateACK {
		e.DupACKs = c.dupACKs
	}
	if dsack != nil {
		e.DSACK = true
		e.Duplicate = recovery.Range{Start: dsack.start, End: dsack.end}
	}
	newLoss := false
	wasRecovering, priorFlight, repeatedLoss := c.recovering, c.flight(), false
	for {
		d := c.detector.Evaluate(e, (*recoveryFlight)(c))
		c.detectorAt = d.Next
		if d.Count > 0 || d.RepairedLoss {
			newLoss = true
			if !c.recovering && kind != recovery.Timeout {
				c.beginRecovery(now)
			}
			if d.RepairedLoss {
				c.lost += uint64(d.RepairedBytes)
				c.undoValid = false
			}
			if d.Count > 0 {
				reloss := false
				values := c.sentSegments()
				for _, loss := range d.Losses[:d.Count] {
					index, found := slices.BinarySearchFunc(values, loss.Start, func(v *sendSegment, seq uint32) int {
						if before(v.seq, seq) {
							return -1
						}
						if after(v.seq, seq) {
							return 1
						}
						return 0
					})
					if !found {
						continue
					}
					v := values[index]
					if v.seq+v.length() != loss.End {
						continue
					}
					reloss = reloss || v.transmissions > 1 && !v.lossReported
					c.markLost(v, now)
				}
				repeatedLoss = repeatedLoss || reloss
			}
		}
		if d.Probe {
			c.sendLossProbe(now)
		}
		if !d.More {
			break
		}
		e.InRecovery = c.recovering
		e.RecoveryDone, e.DSACK = false, false
	}

	if wasRecovering && repeatedLoss && kind != recovery.Timeout && kind != recovery.Reneging {
		c.undoValid = false
		c.controller.OnLoss(congestion.LossEvent{Now: now, BytesInFlight: priorFlight, LostBytes: uint64(c.mss)})
	}
	return newLoss
}

func (c *TCPConn) beginRecovery(now time.Time) {
	c.recovering, c.recover = true, c.sndNxt
	c.undoCount, c.undoProof, c.undoValid = 0, 0, true
	c.controller.OnLoss(congestion.LossEvent{Now: now, BytesInFlight: uint64(c.sndNxt - c.sndUna), LostBytes: uint64(c.mss)})
}

func (c *TCPConn) sendLossProbe(now time.Time) {
	if c.peerWindow == 0 || c.outputWaiting {
		return
	}
	var target *sendSegment
	for _, v := range c.tx.values() {
		if len(v.data) == 0 {
			continue
		}
		if v.transmissions == 0 {
			// RFC 8985 allows one new probe beyond cwnd, but never beyond rwnd.
			if !after(v.seq+v.length(), c.sndUna+c.peerWindow) {
				target = v
			}
			break
		}
		if !v.sacked && !v.lossReported && !v.resend {
			target = v
		}
	}
	if target == nil || !c.transmit(target, now, target.transmissions > 0) {
		return
	}
	c.tailProbes++
	c.detector.Sent(recovery.SentEvent{Segment: recoverySegment(target), Next: c.sndNxt, Probe: true})
	c.rtoAt = now.Add(c.rto)
}

// DSACK is evidence about a duplicate range, not proof that every loss in a
// recovery was spurious. Undo requires an exact, once-retransmitted match for
// every loss, cumulative progress beyond recovery, and no RTO or re-loss.
func (c *TCPConn) proveSpurious(block sackBlock, now time.Time) {
	if !c.undoValid {
		return
	}
	for i, loss := range c.undoRanges[:c.undoCount] {
		if loss == block {
			c.undoProof |= 1 << i
		}
	}
	if c.undoCount == 0 || c.undoProof != uint16((uint32(1)<<c.undoCount)-1) || before(c.sndUna, c.recover) {
		return
	}
	if observer, ok := c.controller.(interface{ OnSpuriousLoss(congestion.AckEvent) }); ok {
		observer.OnSpuriousLoss(congestion.AckEvent{Now: now, Delivered: c.delivered})
		c.spuriousRecoveries++
	}
	c.undoValid = false
}

func splitDSACK(o tcpOptions, ack uint32) (tcpOptions, *sackBlock) {
	if o.count == 0 {
		return o, nil
	}
	b := o.blocks[0]
	if !before(b.start, b.end) {
		return o, nil
	}
	below := !after(b.end, ack)
	contained := o.count > 1 && !before(b.start, o.blocks[1].start) && !after(b.end, o.blocks[1].end)
	if !below && !contained {
		return o, nil
	}
	copy(o.blocks[:], o.blocks[1:o.count])
	o.count--
	return o, &b
}
