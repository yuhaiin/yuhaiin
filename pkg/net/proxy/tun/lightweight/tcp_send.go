package lightweight

import (
	"encoding/binary"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"sort"
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
	if v.transmissions > 0 && !v.lossReported {
		if sacked {
			c.bytesInFlight -= uint64(v.length())
		} else {
			c.bytesInFlight += uint64(v.length())
		}
	}
	v.sacked = sacked
	if sacked {
		v.lossReported = false
		v.resend = false
	}
}
func (c *TCPConn) transmit(v *sendSegment, now time.Time, retrans bool) bool {
	if !c.output(v.seq, v.flags, v.data) {
		return false
	}
	newTransmission := v.transmissions == 0
	restoring := !newTransmission && v.lossReported && !v.sacked
	idle := newTransmission && c.sndUna == c.sndNxt
	if idle {
		c.firstFlight = now
		c.deliveredAt = now
	}
	intentionalLimit := false
	if limiter, ok := c.controller.(congestion.RateSampleLimiter); ok {
		intentionalLimit = limiter.RateSampleLimited()
	}
	if intentionalLimit || newTransmission && len(v.data) > 0 && !c.writePending && v.seq+v.length() == c.sndEnd && c.flight() < c.controller.CongestionWindow() {
		outstanding := uint64(c.sndEnd - (c.iss + uint32(c.delivered)))
		pending := c.flight()
		if newTransmission {
			pending += uint64(v.length())
		}
		c.appLimitedUntil = max(c.delivered+min(pending, outstanding), 1)
	}
	v.delivered = c.delivered
	v.deliveredAt = c.deliveredAt
	v.firstFlight = c.firstFlight
	v.lostAtSend = c.lost
	v.txInFlight = c.flight()
	if newTransmission || restoring {
		v.txInFlight += uint64(v.length())
	}
	if newTransmission {
		v.firstSent = now
	}
	v.appLimited = c.appLimitedUntil > 0
	c.controller.OnPacketSent(congestion.SentPacket{Now: now, Bytes: uint64(v.length()), BytesInFlight: c.flight(), Delivered: c.delivered, AppLimited: v.appLimited, IdleRestart: idle, Retransmission: retrans})
	if newTransmission || restoring {
		c.bytesInFlight += uint64(v.length())
	}
	v.lossReported = false
	if retrans {
		v.retransmitEnd = c.sndNxt
	}
	v.sent = now
	v.resend = false
	v.transmissions++
	if retrans {
		c.stack.retransmissions.Add(1)
	} else {
		c.sndNxt = v.seq + v.length()
	}
	// A byte cwnd need not be an MSS multiple. If the next packet does not
	// fit, the sender is cwnd limited even though flight is slightly below cwnd.
	if before(c.sndNxt, c.sndEnd) {
		next := min(c.mss, int(c.sndEnd-c.sndNxt))
		if c.flight()+uint64(next) > c.controller.CongestionWindow() {
			c.cwndLimited = true
		}
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
		base = maxTime(now.Add(-congestion.DefaultPacingQuantum), previous)
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
	for i := 0; i < c.tx.len() && sent < congestion.DefaultMaxBurstPackets; i++ {
		v := c.tx.values()[i]
		if v.resend || v.lossReported {
			if v.lossReported && c.flight()+uint64(v.length()) > c.controller.CongestionWindow() {
				break
			}
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
				tail := c.stack.buffers.takeSegment()
				*tail = sendSegment{seq: v.seq + uint32(n), flags: v.flags, data: v.data[n:], owner: v.owner}
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

// Transmissions always form a prefix. Do not scan megabytes of queued,
// untransmitted application data for every SACK at a remote bottleneck.
func (c *TCPConn) sentSegments() []*sendSegment {
	values := c.tx.values()
	n := sort.Search(len(values), func(i int) bool { return values[i].transmissions == 0 })
	return values[:n]
}

// deliverySample keeps a value snapshot: ACK processing can release or mutate
// the source descriptor before the controller consumes its timing information.
type deliverySample struct {
	segment sendSegment
	valid   bool
	bytes   uint64
}

func (s *deliverySample) credit(v *sendSegment, n uint32) {
	fresh := n - min(n, v.deliveredBytes)
	if fresh == 0 {
		return
	}
	s.bytes += uint64(fresh)
	if !s.valid || !v.sent.Before(s.segment.sent) {
		s.segment = *v
		s.valid = true
	}
}
func (c *TCPConn) processAck(ack, wnd, seq uint32, o tcpOptions, now time.Time, pure bool) {
	if before(ack, c.sndUna) || after(ack, c.sndNxt) {
		return
	}
	priorFlight := c.flight()
	oldWindow := c.peerWindow
	if c.state != SynSent && c.peerScale > 0 {
		wnd <<= c.peerScale
	}
	if after(seq, c.sndWL1) || seq == c.sndWL1 && !before(ack, c.sndWL2) || c.state == SynSent {
		c.peerWindow = wnd
		c.sndWL1 = seq
		c.sndWL2 = ack
	}
	var sample deliverySample
	validSACK := c.sack && o.count > 0
	for i := range o.count {
		b := o.blocks[i]
		if !before(b.start, b.end) || before(b.start, ack) || after(b.end, c.sndNxt) {
			validSACK = false
		}
	}
	if validSACK {
		for _, v := range c.sentSegments() {
			for i := range o.count {
				b := o.blocks[i]
				if !before(v.seq, b.start) && !after(v.seq+v.length(), b.end) {
					sample.credit(v, v.length())
					v.deliveredBytes = v.length()
					c.setSACK(v, true)
					break
				}
			}
		}
	}
	acked := uint64(ack - c.sndUna)
	rtt := time.Duration(0)
	ambiguous := false
	if acked > 0 {
		c.sndUna = ack
		c.dupACKs = 0
		c.retries = 0
		for c.tx.len() > 0 {
			v := c.tx.values()[0]
			if v.transmissions == 0 || !after(ack, v.seq) {
				break
			}
			n := min(uint32(ack-v.seq), v.length())
			sample.credit(v, n)
			if v.transmissions == 1 {
				rtt = now.Sub(v.firstSent)
			} else {
				ambiguous = true
			}
			if !v.sacked && !v.lossReported {
				c.bytesInFlight -= uint64(n)
			}
			if n == v.length() {
				c.tx.pop()
				c.txBytes -= len(v.data)
				fin := v.flags&flagFIN != 0
				c.stack.buffers.releaseSegment(v)
				if fin {
					c.finAcked(now)
				}
			} else {
				if n > uint32(len(v.data)) {
					break
				}
				v.deliveredBytes -= min(n, v.deliveredBytes)
				v.data = v.data[n:]
				v.seq = ack
				c.txBytes -= int(n)
				break
			}
		}
	}
	// An advancing ACK stopping at a SACKed head suggests receiver reneging.
	// ACKs themselves can reorder: give a newer ACK a bounded grace period.
	suspectReneging := acked > 0 && c.tx.len() > 0 && c.tx.values()[0].sacked
	c.delivered += sample.bytes
	if c.tx.len() == 0 || !c.tx.values()[0].sacked {
		c.renegeAt = time.Time{}
	}
	if suspectReneging && c.renegeAt.IsZero() {
		c.renegeAt = now.Add(max(c.srtt/2, 10*time.Millisecond))
	}
	if sample.bytes > 0 {
		c.deliveredAt = now
	}
	if c.appLimitedUntil > 0 && c.delivered > c.appLimitedUntil {
		c.appLimitedUntil = 0
	}
	if ambiguous {
		rtt = 0
	}
	if rtt > 0 {
		c.updateRTT(rtt)
	}
	newLoss := false
	if validSACK {
		newLoss = c.inferSACKLoss(now)
	}
	event := congestion.AckEvent{Now: now, AckedBytes: acked, PriorInFlight: priorFlight, NewlyDelivered: sample.bytes, BytesInFlight: c.flight(), Delivered: c.delivered, PriorDelivered: c.delivered - sample.bytes, RTT: rtt, ACK: ack, NextSeq: c.sndNxt, CwndLimited: c.cwndLimited || priorFlight >= c.controller.CongestionWindow(), PacingDelay: max(c.paceAt.Sub(now), 0)}
	c.cwndLimited = false
	if sample.valid {
		v := &sample.segment
		interval := max(now.Sub(v.deliveredAt), v.sent.Sub(v.firstFlight))
		event.PriorDelivered = v.delivered
		event.SampleDelivered = c.delivered - v.delivered
		event.SampleLost = c.lost - v.lostAtSend
		event.TxInFlight = v.txInFlight
		event.AppLimited = v.appLimited
		if interval > 0 {
			event.DeliveryRate = uint64(float64(event.SampleDelivered) / interval.Seconds())
			event.RateSample = event.DeliveryRate > 0
			c.firstFlight = v.sent
		}
	}
	if suspectReneging {
		event.RateSample = false
		event.DeliveryRate = 0
	}
	if newLoss && !c.recovering {
		c.recovering = true
		c.recover = c.sndNxt
		c.controller.OnLoss(congestion.LossEvent{Now: now, BytesInFlight: uint64(c.sndNxt - c.sndUna), LostBytes: uint64(c.mss)})
		c.retransmit(now)
	}
	if acked == 0 {
		if pure && wnd == oldWindow && c.sndUna != c.sndNxt {
			c.dupACKs++
			headOriginal := c.tx.len() > 0 && c.tx.values()[0].transmissions == 1 && !c.tx.values()[0].resend
			if c.dupACKs == 3 && !c.recovering && headOriginal {
				c.recovering = true
				c.recover = c.sndNxt
				c.controller.OnLoss(congestion.LossEvent{Now: now, BytesInFlight: uint64(c.sndNxt - c.sndUna), LostBytes: uint64(c.mss)})
				c.retransmit(now)
			} else if c.recovering {
				event.InRecovery = true
				c.ackController(event)
				return
			}
		}
		if sample.bytes > 0 {
			event.InRecovery = c.recovering
			c.ackController(event)
		}
		return
	}
	recovered := c.recovering && !before(ack, c.recover)
	event.InRecovery = c.recovering
	event.RecoveryDone = recovered
	c.ackController(event)
	if recovered {
		c.recovering = false
	} else if c.recovering {
		// A partial NewReno ACK identifies the next original loss. Already
		// retransmitted data remains in flight until stronger evidence or an RTO.
		for _, v := range c.tx.values() {
			if v.transmissions > 0 && !v.sacked {
				if v.transmissions == 1 {
					c.markLost(v, now)
				}
				break
			}
		}
	}
	if c.sndUna == c.sndNxt {
		c.rtoAt = time.Time{}
	} else {
		c.rtoAt = now.Add(c.rto)
	}
	notify(&c.writeChanged)
}
func (c *TCPConn) ackController(event congestion.AckEvent) {
	event.BytesInFlight = c.flight()
	event.LostBytes = c.lost - c.lossAtACK
	c.lossAtACK = c.lost
	c.controller.OnAck(event)
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
