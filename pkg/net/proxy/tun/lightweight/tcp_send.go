package lightweight

import (
	"encoding/binary"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"time"
)

func (c *TCPConn) receiveWindow() uint32 {
	free := uint32(max(0, c.receiveLimit-c.rxBytes))
	if before(c.rcvNxt+free, c.rcvAdv) {
		free = c.rcvAdv - c.rcvNxt
	}
	return free
}
func (c *TCPConn) headerOptions(dst []byte, syn bool) []byte {
	if syn {
		b := dst[:12]
		copy(b, []byte{2, 4, byte(c.pathMSS >> 8), byte(c.pathMSS), 4, 2, 1, 3, 3, byte(c.ownScale), 1, 1})
		return b
	}
	if !c.sack || len(c.ooo) == 0 {
		return nil
	}
	var blocks [4]sackBlock
	n := 0
	for _, v := range c.ooo {
		end := v.seq + uint32(len(v.data))
		if n > 0 && blocks[n-1].end == v.seq {
			blocks[n-1].end = end
			continue
		}
		if n == len(blocks) {
			break
		}
		blocks[n] = sackBlock{v.seq, end}
		n++
	}
	b := dst[:4+8*n]
	b[0] = 1
	b[1] = 1
	b[2] = 5
	b[3] = byte(2 + 8*n)
	for i := range n {
		binary.BigEndian.PutUint32(b[4+8*i:], blocks[i].start)
		binary.BigEndian.PutUint32(b[8+8*i:], blocks[i].end)
	}
	return b
}
func (c *TCPConn) output(seq uint32, flags uint8, data []byte) bool {
	syn := flags&flagSYN != 0
	var options [40]byte
	opts := c.headerOptions(options[:], syn)
	// SACK blocks occupy TCP option space and reduce this packet's usable MSS.
	// A full-sized data segment can omit SACK; the cumulative ACK still applies.
	if len(data) > c.pathMSS-len(opts) {
		opts = nil
	}
	// Bound the untrusted payload before adding header sizes. This also makes
	// allocation arithmetic safe on 32-bit targets.
	maxData := 65535 - 20 - len(opts)
	if c.key.local.Addr().Is4() {
		maxData -= 20
	}
	maxData = min(maxData, c.pathMSS-len(opts))
	if len(data) > maxData {
		c.finish(ErrMTU)
		return false
	}
	packet, ih, err := c.stack.ipBuffer(c.key.local.Addr(), c.key.remote.Addr(), 6, 20+len(opts)+len(data))
	if err != nil {
		if errors.Is(err, ErrLimit) {
			c.waitOutput(ih + 20 + len(opts) + len(data))
		} else {
			c.finish(err)
		}
		return false
	}
	b := packet.data[ih:]
	clear(b[:20])
	binary.BigEndian.PutUint16(b[:2], c.key.local.Port())
	binary.BigEndian.PutUint16(b[2:4], c.key.remote.Port())
	binary.BigEndian.PutUint32(b[4:8], seq)
	if c.state != SynSent || !syn {
		flags |= flagACK
		binary.BigEndian.PutUint32(b[8:12], c.rcvNxt)
	}
	b[12] = byte((20+len(opts))/4) << 4
	b[13] = flags
	window := c.receiveWindow()
	shift := c.ownScale
	if syn {
		shift = 0
	}
	scaled := min(window>>shift, 65535)
	binary.BigEndian.PutUint16(b[14:16], uint16(scaled))

	copy(b[20:], opts)
	copy(b[20+len(opts):], data)
	binary.BigEndian.PutUint16(b[16:18], transportChecksum(c.key.local.Addr(), c.key.remote.Addr(), 6, b))
	if err := c.stack.emitOwned(packet); err != nil {
		packet.release()
		if errors.Is(err, ErrLimit) {
			h := 20
			if c.key.local.Addr().Is6() {
				h = 40
			}
			c.waitOutput(len(b) + h)
			if flags == flagACK && len(data) == 0 {
				c.ackPending = max(c.ackPending, 1)
			}
		} else {
			c.finish(err)
		}
		return false
	}
	if !syn {
		// Window scaling rounds the wire field down. Keep the greatest right
		// edge already offered: older in-flight data remains acceptable even
		// when this ACK's quantized field represents a slightly smaller edge.
		edge := c.rcvNxt + (scaled << shift)
		if after(edge, c.rcvAdv) {
			c.rcvAdv = edge
		}
	}
	if flags&flagACK != 0 {
		c.ackPending = 0
		c.ackAt = time.Time{}
	}
	return true
}
func (c *TCPConn) sendACK() {
	if !c.output(c.sndNxt, flagACK, nil) {
		c.schedule(time.Now())
	}
}
func (c *TCPConn) sendReset()     { c.output(c.sndNxt, flagRST|flagACK, nil) }
func (c *TCPConn) flight() uint64 { return c.bytesInFlight }

func (c *TCPConn) setSACK(v *sendSegment, sacked bool) {
	if v.sacked == sacked {
		return
	}
	if v.transmissions > 0 {
		if sacked {
			c.bytesInFlight -= uint64(v.length())
		} else {
			c.bytesInFlight += uint64(v.length())
		}
	}
	v.sacked = sacked
}
func (c *TCPConn) transmit(v *sendSegment, now time.Time, retrans bool) bool {
	if !c.output(v.seq, v.flags, v.data) {
		return false
	}
	if v.transmissions == 0 {
		if c.sndUna == c.sndNxt {
			c.firstFlight = now
			c.deliveredAt = now
		}
		v.firstSent = now
		v.delivered = c.delivered
		v.deliveredAt = c.deliveredAt
		v.firstFlight = c.firstFlight
		// A large cwnd alone does not imply application limitation. A paced
		// sender can have a full write backlog while using only a small flight.
		v.appLimited = v.seq+v.length() == c.sndEnd && c.flight() < c.controller.CongestionWindow()
		c.controller.OnPacketSent(congestion.SentPacket{Now: now, Bytes: uint64(v.length()), BytesInFlight: c.flight(), Delivered: c.delivered, AppLimited: v.appLimited})
		c.bytesInFlight += uint64(v.length())
	}
	v.sent = now
	v.resend = false
	v.transmissions++
	if retrans {
		c.stack.retransmissions.Add(1)
	} else {
		c.sndNxt = v.seq + v.length()
	}
	rate := c.controller.PacingRate()
	if rate > 0 {
		c.paceAt = pacingDeadline(now, c.paceAt, v.length(), rate)
	}
	if c.rtoAt.IsZero() {
		c.rtoAt = now.Add(c.rto)
	}
	return true
}
func pacingDeadline(now, previous time.Time, bytes uint32, rate uint64) time.Time {
	spacing := time.Duration(float64(bytes) / float64(rate) * float64(time.Second))
	// Preserve earned pacing credit when the shared timer runs late. Restarting
	// from now on every packet turns timer granularity into a throughput cap.
	// At most one millisecond of credit is retained; cwnd and the 64-packet pump
	// budget independently bound a catch-up burst. Idle time cannot accumulate.
	base := now
	if !previous.IsZero() {
		base = maxTime(now.Add(-time.Millisecond), previous)
	}
	return base.Add(max(spacing, time.Nanosecond))
}
func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
func (c *TCPConn) pump(now time.Time) {
	if c.outputWaiting || c.state == Closed || c.state == TimeWait {
		c.schedule(now)
		return
	}
	sent := 0
	for i := 0; i < c.tx.len() && sent < 64; i++ {
		v := c.tx.values()[i]
		if v.resend {
			// PMTU replacements reuse already admitted sequence space. They do not
			// consume a new congestion/window allowance or advance sndNxt.
			if !c.paceAt.IsZero() && now.Before(c.paceAt) {
				break
			}
			if !c.transmit(v, now, true) {
				break
			}
			sent++
			continue
		}
		if v.transmissions > 0 {
			continue
		}
		if v.flags&flagSYN == 0 {
			if c.state == SynSent || c.state == SynReceived {
				break
			}
			if !c.paceAt.IsZero() && now.Before(c.paceAt) {
				break
			}
			right := c.sndUna + c.peerWindow
			if !before(v.seq, right) {
				break
			}
			available := uint64(right - v.seq)
			flight := c.flight()
			cwnd := c.controller.CongestionWindow()
			if flight >= cwnd {
				break
			}
			available = min(available, cwnd-flight, uint64(c.mss))
			if available < uint64(v.length()) {
				if len(v.data) == 0 || available == 0 || flight > 0 {
					break
				}
				// Split only untransmitted buffers. Ownership/accounting stays with the
				// backing allocation; both read-only views retain it until ACKed.
				n := int(available)
				if n >= len(v.data) {
					break
				}
				if c.tx.len() >= maxSendSegments || !c.stack.reserve(segmentCharge) {
					c.finish(ErrLimit)
					return
				}
				v.owner.hold()
				tail := &sendSegment{seq: v.seq + uint32(n), flags: v.flags, data: v.data[n:], owner: v.owner}
				v.data = v.data[:n]
				c.tx.insert(i+1, tail)
			}
		}
		if !c.transmit(v, now, false) {
			break
		}
		sent++
	}
	if c.peerWindow == 0 && c.tx.len() > 0 && c.persistAt.IsZero() {
		c.persistAt = now.Add(c.rto)
	}
	if c.peerWindow > 0 {
		c.persistAt = time.Time{}
	}
	c.schedule(now)
}

func (c *TCPConn) processAck(ack, wnd, seq uint32, o tcpOptions, now time.Time, pure bool) {
	if before(ack, c.sndUna) || after(ack, c.sndNxt) {
		return
	}
	oldWindow := c.peerWindow
	if c.state != SynSent && c.peerScale > 0 {
		wnd <<= c.peerScale
	}
	if after(seq, c.sndWL1) || seq == c.sndWL1 && !before(ack, c.sndWL2) || c.state == SynSent {
		c.peerWindow = wnd
		c.sndWL1 = seq
		c.sndWL2 = ack
	}
	// Validate the entire SACK option before using any block. SACK never frees
	// retransmission memory; only a cumulative ACK can do that (RFC 2018).
	validSACK := c.sack
	for i := range o.count {
		b := o.blocks[i]
		if !before(b.start, b.end) || before(b.start, ack) || after(b.end, c.sndNxt) {
			validSACK = false
		}
	}
	if validSACK {
		for _, v := range c.tx.values() {
			if v.transmissions == 0 {
				continue
			}
			for i := range o.count {
				b := o.blocks[i]
				if !before(v.seq, b.start) && !after(v.seq+v.length(), b.end) {
					c.setSACK(v, true)
				}
			}
		}
	}
	if ack == c.sndUna {
		if pure && wnd == oldWindow && c.sndUna != c.sndNxt {
			c.dupACKs++
			if c.dupACKs == 3 && !c.recovering {
				c.recovering = true
				c.recover = c.sndNxt
				c.controller.OnLoss(congestion.LossEvent{Now: now, BytesInFlight: uint64(c.sndNxt - c.sndUna), LostBytes: uint64(c.mss)})
				c.retransmit(now)
			} else if c.recovering {
				c.controller.OnAck(congestion.AckEvent{Now: now, InRecovery: true})
			}
		}
		return
	}
	acked := uint64(ack - c.sndUna)
	c.sndUna = ack
	c.dupACKs = 0
	c.retries = 0
	var sample sendSegment
	haveSample := false
	ambiguous := false
	rtt := time.Duration(0)
	released := 0
	for c.tx.len() > 0 {
		v := c.tx.values()[0]
		if v.transmissions == 0 || !after(ack, v.seq) {
			break
		}
		if v.transmissions == 1 {
			sample = *v
			haveSample = true
			rtt = now.Sub(v.firstSent)
		} else {
			ambiguous = true
		}
		if !before(ack, v.seq+v.length()) {
			if !v.sacked {
				c.bytesInFlight -= uint64(v.length())
			}
			c.tx.pop()
			c.txBytes -= len(v.data)
			released += segmentMemory(v)
			v.owner.release()
			if v.flags&flagFIN != 0 {
				c.finAcked(now)
			}
		} else {
			n := int(ack - v.seq)
			if n > len(v.data) {
				break
			}
			// Keep a bounded view of the original allocation until the final ACK.
			// Its entire capacity remains charged, even after a partial ACK.
			if !v.sacked {
				c.bytesInFlight -= uint64(n)
			}
			v.data = v.data[n:]
			v.seq = ack
			c.txBytes -= n
			break
		}
	}
	c.stack.release(released)
	c.delivered += acked
	c.deliveredAt = now
	// A cumulative ACK covering any retransmission cannot identify which
	// transmission it acknowledges (Karn, RFC 6298 section 3).
	if ambiguous {
		rtt = 0
	}
	if rtt > 0 {
		c.updateRTT(rtt)
	}
	rate := uint64(0)
	prior := c.delivered - acked
	appLimited := false
	if haveSample {
		c.firstFlight = sample.firstSent
		interval := max(now.Sub(sample.deliveredAt), sample.firstSent.Sub(sample.firstFlight))
		if interval > 0 {
			rate = uint64(float64(c.delivered-sample.delivered) / interval.Seconds())
		}
		prior = sample.delivered
		appLimited = sample.appLimited
	}
	recovered := c.recovering && !before(ack, c.recover)
	c.controller.OnAck(congestion.AckEvent{Now: now, AckedBytes: acked, BytesInFlight: c.flight(), Delivered: c.delivered, PriorDelivered: prior, DeliveryRate: rate, RTT: rtt, AppLimited: appLimited, InRecovery: c.recovering, RecoveryDone: recovered})
	if recovered {
		c.recovering = false
	} else if c.recovering {
		c.retransmit(now)
	}
	if c.sndUna == c.sndNxt {
		c.rtoAt = time.Time{}
	} else {
		c.rtoAt = now.Add(c.rto)
	}
	notify(&c.changed)
}
func (c *TCPConn) updateRTT(r time.Duration) {
	if c.srtt == 0 {
		c.srtt = r
		c.rttvar = r / 2
	} else {
		delta := c.srtt - r
		if delta < 0 {
			delta = -delta
		}
		c.rttvar = (3*c.rttvar + delta) / 4
		c.srtt = (7*c.srtt + r) / 8
	}
	c.rto = min(time.Minute, max(time.Second, c.srtt+max(time.Millisecond, 4*c.rttvar)))
}
func (c *TCPConn) finAcked(now time.Time) {
	switch c.state {
	case FinWait1:
		if c.recvFIN {
			c.enterTimeWait(now)
		} else {
			c.state = FinWait2
			c.endAt = now.Add(2 * time.Minute)
		}
	case Closing:
		c.enterTimeWait(now)
	case LastAck:
		c.finish(nil)
	}
}
func (c *TCPConn) enterTimeWait(now time.Time) {
	c.state = TimeWait
	c.endAt = now.Add(c.stack.config.TimeWait)
	c.rtoAt = time.Time{}
	c.persistAt = time.Time{}
	c.paceAt = time.Time{}
}
