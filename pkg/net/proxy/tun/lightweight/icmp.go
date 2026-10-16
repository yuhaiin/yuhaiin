package lightweight

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"net/netip"
	"time"
)

func (s *Stack) allowICMP() bool {
	s.icmpMu.Lock()
	defer s.icmpMu.Unlock()
	now := time.Now().UnixNano()
	if s.icmpStamp != 0 {
		s.icmpTokens = min(100, s.icmpTokens+float64(now-s.icmpStamp)/float64(time.Second)*100)
	}
	s.icmpStamp = now
	if s.icmpTokens < 1 {
		return false
	}
	s.icmpTokens--
	return true
}
func (s *Stack) handleICMP(p Packet) {
	b := p.Payload
	echo, reply := byte(8), byte(0)
	if p.Protocol == 58 {
		echo = 128
		reply = 129
	}
	if b[0] == echo && b[1] == 0 {
		if !s.allowICMP() {
			return
		}
		out := bytes.Clone(b)
		out[0] = reply
		out[2] = 0
		out[3] = 0
		checksum := Checksum(out)
		if p.Protocol == 58 {
			checksum = transportChecksum(p.Destination, p.Source, 58, out)
		}
		binary.BigEndian.PutUint16(out[2:4], checksum)
		if err := s.sendDatagram(flowAddress{p.Destination}, flowAddress{p.Source}, p.Protocol, out); err != nil {
			s.drops.Add(1)
		}
		return
	}
	isError := p.Protocol == 1 && (b[0] == 3 || b[0] == 11 || b[0] == 12) || p.Protocol == 58 && b[0] < 128
	if !isError {
		return
	}
	s.handleICMPError(p)
}
func (s *Stack) icmpError(p Packet, typ, code byte, mtu uint32) {
	if !s.allowICMP() || p.FragmentOffset != 0 || p.Source.IsUnspecified() || p.Source.IsMulticast() || p.Destination.IsMulticast() {
		return
	}
	if (p.Protocol == 1 && len(p.Payload) > 0 && (p.Payload[0] == 3 || p.Payload[0] == 11 || p.Payload[0] == 12)) || (p.Protocol == 58 && len(p.Payload) > 0 && p.Payload[0] < 128) {
		return
	}
	proto := byte(1)
	quote := min(len(p.Data), s.config.MTU-28)
	if p.Source.Is6() {
		proto = 58
		quote = min(len(p.Data), 1232)
		switch typ {
		case 11:
			typ = 3
		case 3:
			if code == 4 {
				typ = 2
				code = 0
			} else {
				typ = 1
				if code == 3 {
					code = 4
				}
			}
		}
	}
	b := make([]byte, 8+quote)
	b[0] = typ
	b[1] = code
	copy(b[8:], p.Data[:quote])
	if mtu > 0 {
		if proto == 1 {
			binary.BigEndian.PutUint16(b[6:8], uint16(min(mtu, 65535)))
		} else {
			binary.BigEndian.PutUint32(b[4:8], mtu)
		}
	}
	sum := Checksum(b)
	if proto == 58 {
		sum = transportChecksum(p.Destination, p.Source, 58, b)
	}
	binary.BigEndian.PutUint16(b[2:4], sum)
	_ = s.sendIP(p.Destination, p.Source, proto, b)
}

// ICMP quotations are intentionally truncated IP packets; parse just enough
// bounded header data to associate an error with a live transport tuple.
func quotedTransport(b []byte) (flowKey, uint8, []byte, bool) {
	var src, dst netip.Addr
	off := 0
	proto := byte(0)
	if len(b) < 20 {
		return flowKey{}, 0, nil, false
	}
	switch b[0] >> 4 {
	case 4:
		off = int(b[0]&15) * 4
		if off < 20 || off+8 > len(b) || binary.BigEndian.Uint16(b[6:8])&8191 != 0 {
			return flowKey{}, 0, nil, false
		}
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		proto = b[9]
	case 6:
		if len(b) < 48 {
			return flowKey{}, 0, nil, false
		}
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		off = 40
		proto = b[6]
		for i := 0; proto == 0 || proto == 60 || proto == 43; i++ {
			if i >= 8 || off+2 > len(b) {
				return flowKey{}, 0, nil, false
			}
			n := (int(b[off+1]) + 1) * 8
			if off+n+8 > len(b) {
				return flowKey{}, 0, nil, false
			}
			proto = b[off]
			off += n
		}
		if proto == 44 {
			if off+16 > len(b) || binary.BigEndian.Uint16(b[off+2:off+4])&0xfff8 != 0 {
				return flowKey{}, 0, nil, false
			}
			proto = b[off]
			off += 8
		}
	default:
		return flowKey{}, 0, nil, false
	}
	if off+8 > len(b) {
		return flowKey{}, 0, nil, false
	}
	t := b[off:]
	return flowKey{netip.AddrPortFrom(src, binary.BigEndian.Uint16(t[:2])), netip.AddrPortFrom(dst, binary.BigEndian.Uint16(t[2:4]))}, proto, t, true
}
func (s *Stack) handleICMPError(p Packet) {
	b := p.Payload
	k, proto, q, ok := quotedTransport(b[8:])
	if !ok {
		return
	}
	tooBig := p.Protocol == 1 && b[0] == 3 && b[1] == 4 || p.Protocol == 58 && b[0] == 2
	mtu := 0
	if tooBig {
		if p.Protocol == 1 {
			mtu = int(binary.BigEndian.Uint16(b[6:8]))
		} else {
			mtu = int(binary.BigEndian.Uint32(b[4:8]))
		}
	}
	err := errors.New("lightweight: ICMP destination unreachable")
	if p.Protocol == 1 && b[0] == 11 || p.Protocol == 58 && b[0] == 3 {
		err = errors.New("lightweight: ICMP time exceeded")
	}
	switch proto {
	case 6:
		c := s.find(k)
		if c == nil {
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		seq := binary.BigEndian.Uint32(q[4:8])
		if before(seq, c.sndUna) || !before(seq, c.sndNxt) {
			return
		}
		if tooBig {
			minMTU, h := 68, 40
			if k.local.Addr().Is6() {
				minMTU, h = 1280, 60
			}
			if mtu < minMTU {
				mtu = minMTU
			}
			if mtu-h >= c.pathMSS {
				return
			}
			c.pathMSS = max(28, mtu-h)
			c.mss = min(c.mss, c.pathMSS)
			if updater, ok := c.controller.(congestion.MSSUpdater); ok {
				updater.UpdateMSS(uint64(c.mss))
			}
			c.resegment()
			c.pump(time.Now())
			return
		}
		if c.state == SynSent || c.state == SynReceived {
			c.finish(err)
		} // Established TCP treats these as soft errors.
	case 17:
		s.mu.Lock()
		u := s.udp[k.local]
		s.mu.Unlock()
		if u != nil {
			u.mu.Lock()
			if !u.closed && u.remote == k.remote {
				if tooBig {
					u.err = ErrMTU
				} else {
					u.err = err
				}
				notify(&u.changed)
			}
			u.mu.Unlock()
		}
	}
}
func (c *TCPConn) resegment() {
	extra := 0
	for _, v := range c.tx.values() {
		if len(v.data) > c.mss {
			extra += (len(v.data) - 1) / c.mss
		}
	}
	if c.tx.len()+extra > maxSendSegments || !c.stack.reserve(extra*segmentCharge) {
		c.finish(ErrLimit)
		return
	}
	var tx []*sendSegment
	for _, v := range c.tx.values() {
		// All outstanding data may have met the old path limit. Keep transmission
		// history for Karn and cumulative ACKs, but explicitly schedule replacement
		// packets rather than making them appear to be newly sent sequence space.
		if v.transmissions > 0 && len(v.data) > 0 {
			v.resend = true
			c.setSACK(v, false)
		}
		if len(v.data) <= c.mss {
			tx = append(tx, v)
			continue
		}
		original := *v
		for off := 0; off < len(original.data); off += c.mss {
			end := min(len(original.data), off+c.mss)
			part := v
			if off > 0 {
				part = c.stack.buffers.takeSegment()
				original.owner.hold()
			}
			*part = original
			part.seq += uint32(off)
			part.data = original.data[off:end]
			part.deliveredBytes = min(uint32(end-off), original.deliveredBytes-min(original.deliveredBytes, uint32(off)))
			part.sacked = false
			tx = append(tx, part)
		}
	}
	c.tx = sliceQueue[*sendSegment]{items: tx}
}
