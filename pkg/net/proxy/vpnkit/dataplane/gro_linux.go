//go:build linux

package dataplane

// Userspace GRO: the write-side mirror of offload_linux.go's TSO, and the last
// piece of doc/scaling-the-data-path.md's Option 1.
//
// Inbound bulk TCP arrives off the tunnel as one decapsulated packet per
// datagram, and each cost one TUN write. Within one read batch, consecutive
// segments of the same flow are coalesced into a super-frame written once,
// with a virtio-net header carrying real GSO metadata: NEEDS_CSUM plus the
// pseudo-header sum in the checksum field, exactly the CHECKSUM_PARTIAL form
// the kernel's own GRO produces, so the stack delivers it locally or
// re-segments it on forward without ever walking a bogus checksum.
//
// The merge rules follow kernel GRO, conservatively: IPv4 without options,
// TCP with identical headers apart from seq / IP id / checksums (PSH or FIN
// may arrive on a segment — it is folded in and closes the group), sequence
// numbers exactly contiguous, IP IDs sequential under DF, payload sizes never
// growing (a short segment closes its group, matching gso_size semantics),
// and — like the kernel — a segment's TCP checksum is VERIFIED before it may
// merge, because a coalesced frame is marked CHECKSUM_PARTIAL and nothing
// downstream would catch the corruption. Anything that fails a rule is
// written through unmodified in arrival order, so GRO can only ever reduce
// syscalls, never change what the stack sees.

import (
	"encoding/binary"
	"net"
)

const (
	// groMaxLen caps a coalesced frame at what an IPv4 total-length field can
	// carry.
	groMaxLen   = 65535
	tcpFlagACK  = 0x10
	tcpFlagMask = 0x3f // FIN|SYN|RST|PSH|ACK|URG
)

// groGroup is one open coalescing group: the first segment's headers plus the
// accumulated payloads, and the state deciding what may still append.
type groGroup struct {
	buf     []byte // headers + payloads accumulated; cap groMaxLen
	length  int
	segs    int
	gsoSize int    // first segment's payload size; later ones must not exceed it
	nextSeq uint32 // sequence number the next segment must carry
	nextID  uint16 // IP ID the next segment must carry
	closed  bool   // a short / PSH / FIN segment ended the group
}

// groTable is the per-batch working set of open groups. It lives on the Pump
// and is reused across batches — owned by the single inbound goroutine — so a
// steady-state batch allocates nothing.
type groTable struct {
	groups []*groGroup
	n      int
	// hdr is the virtio-net header scratch for GSO flushes; a stack array
	// would escape through the vnetWriteGSO function pointer and cost an
	// allocation per flush.
	hdr [virtioNetHdrLen]byte
}

func (t *groTable) reset() { t.n = 0 }

// grab returns a cleared group, reusing storage.
func (t *groTable) grab() *groGroup {
	if t.n == len(t.groups) {
		t.groups = append(t.groups, &groGroup{buf: make([]byte, 0, groMaxLen)})
	}
	g := t.groups[t.n]
	t.n++
	g.length, g.segs, g.gsoSize, g.closed = 0, 0, 0, false
	return g
}

// handleInboundBatchGRO is HandleInboundBatch on a vnet TUN: decapsulate each
// datagram, coalesce what the rules allow, write everything else through in
// order. Always returns true (it is the vnet batch path).
//
// The MultiTunnel branch is not an optimisation and must not be dropped. This
// path used to call decapInbound unconditionally -- the one-datagram-one-packet
// decapsulator -- which meant that on any TUN that negotiated the vnet header,
// an aggregating tunnel's inbound packets went to the wrong method. For IKEv2's
// AGGFRAG tunnel that is not a lost aggregation: espTunnel.Decapsulate rejects
// next header 144 outright, so EVERY inbound packet was dropped as malformed
// while the handshake reported IP-TFS negotiated and working.
//
// It was invisible from three directions at once. dataplane's own tests use a
// plain TUN, so they exercise HandleInbound (which does check). The veepin
// client negotiates GSO, so the real path is this one. And a veepin-to-veepin
// cell fails identically at both ends, which reads as "the tunnel is down"
// rather than "the receive path is wrong".
func (p *Pump) handleInboundBatchGRO(v *view, pkts [][]byte, froms []*net.UDPAddr, now int64) bool {
	t := &p.gro
	t.reset()
	for i, pkt := range pkts {
		var from *net.UDPAddr
		if froms != nil {
			from = froms[i]
		}
		b, key, ok := p.lookupInbound(v, pkt)
		if !ok {
			continue
		}
		if b.multi != nil {
			// An aggregated datagram carries several inner packets, so it
			// cannot go through decapInbound's single-packet return. Deliver
			// its contents through the same coalescing table as everything
			// else -- a bulk TCP flow inside an IP-TFS tunnel deserves GRO as
			// much as one outside it.
			p.groMulti(t, b, pkt, from, now)
			continue
		}
		inner, ok := p.decapInbound(b, key, pkt, from, now)
		if !ok {
			continue
		}
		// Counted here rather than at the TUN write, because coalescing means
		// one write can carry several packets: counting writes would report a
		// GRO-enabled server as moving a fraction of the traffic it moved.
		b.c.countRx(len(inner), now)
		if !t.add(p, inner) {
			// Not coalescible (or its checksum did not verify): deliver as-is,
			// in arrival order.
			if _, err := p.writeTUN(inner); err != nil {
				p.drops[DropTUNWrite].Add(1)
				if p.log != nil {
					p.log.Warnf("dataplane: TUN write failed: %v", err)
				}
			}
		}
	}
	for _, g := range t.groups[:t.n] {
		g.flush(p)
	}
	return true
}

// groMulti opens one aggregated datagram and offers each inner packet to the
// coalescing table, falling back to a direct TUN write for the ones GRO does
// not handle. It is handleInboundMulti with the table in the middle.
func (p *Pump) groMulti(t *groTable, b bound, pkt []byte, from *net.UDPAddr, now int64) {
	inners, ok := p.decapMulti(b, pkt, from, now)
	if !ok {
		return
	}
	for _, inner := range inners {
		if len(inner) == 0 {
			continue
		}
		// Per inner packet, as handleInboundMulti counts: counting datagrams
		// would report an IP-TFS tunnel moving a fraction of what it moved.
		b.c.countRx(len(inner), now)
		if t.add(p, inner) {
			continue
		}
		if _, err := p.writeTUN(inner); err != nil {
			p.drops[DropTUNWrite].Add(1)
			if p.log != nil {
				p.log.Warnf("dataplane: TUN write failed: %v", err)
			}
			return
		}
	}
}

// coalescible reports whether pkt is the kind of packet GRO handles at all:
// well-formed IPv4 without options, TCP without SYN/RST/URG, DF set, no
// fragmentation, and a non-empty payload.
func coalescible(pkt []byte) bool {
	if len(pkt) < 40 || pkt[0] != 0x45 || pkt[9] != protoTCP {
		return false
	}
	if int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
		return false
	}
	// DF required, no fragments: frag field must be exactly 0x4000.
	if binary.BigEndian.Uint16(pkt[6:8]) != 0x4000 {
		return false
	}
	thl := int(pkt[32]>>4) * 4
	if thl < 20 || len(pkt) < 20+thl {
		return false
	}
	flags := pkt[33] & tcpFlagMask
	if flags&^(tcpFlagACK|tcpFlagPSH|tcpFlagFIN) != 0 || flags&tcpFlagACK == 0 {
		return false // SYN/RST/URG, or not an established-flow segment
	}
	return len(pkt) > 20+thl // payload required; pure ACKs pass through
}

// tcpChecksumOK verifies pkt's TCP checksum the way a receiver would. GRO may
// only merge verified segments: a coalesced frame is marked CHECKSUM_PARTIAL,
// which tells the kernel there is nothing left to check.
func tcpChecksumOK(pkt []byte) bool {
	acc := onesComplementSum(0, pkt[12:20])
	acc += protoTCP + uint32(len(pkt)-20)
	acc = onesComplementSum(acc, pkt[20:])
	return foldSum(acc) == 0xffff
}

// add offers pkt to the table: append to its flow's open group, open a new
// group, or — when the flow's group cannot take it — flush that group first so
// intra-flow order holds. It reports false when pkt is not coalescible (or
// fails verification) and the caller must write it through unchanged; in that
// case too, any open group of the same flow is flushed first, so the
// pass-through packet cannot overtake segments already held (a pure ACK, an
// RST, or a corrupted segment must reach the stack after the data before it).
func (t *groTable) add(p *Pump, pkt []byte) bool {
	if !coalescible(pkt) || !tcpChecksumOK(pkt) {
		t.flushSameFlow(p, pkt)
		return false
	}
	for _, g := range t.groups[:t.n] {
		if !g.sameFlow(pkt) {
			continue
		}
		if g.canAppend(pkt) {
			g.append(pkt)
			return true
		}
		// Same flow, unmergeable (closed group, sequence jump, changed ack or
		// window, growing payload, size cap): flush what is held, then let the
		// packet start over as a fresh group, preserving flow order.
		g.flush(p)
		g.start(pkt)
		return true
	}
	t.grab().start(pkt)
	return true
}

// sameFlow reports whether pkt belongs to the group's 4-tuple.
func (g *groGroup) sameFlow(pkt []byte) bool {
	// src+dst addresses (12:20) and src+dst ports (20:24) in one compare.
	return string(g.buf[12:24]) == string(pkt[12:24])
}

// flushSameFlow flushes the open group, if any, matching a pass-through
// packet's flow — when the packet parses far enough to name one (options-free
// IPv4/TCP, like every group). Anything else (non-TCP, IP options) has no
// intra-flow ordering contract with the TCP groups, the same position kernel
// GRO takes.
func (t *groTable) flushSameFlow(p *Pump, pkt []byte) {
	if len(pkt) < 24 || pkt[0] != 0x45 || pkt[9] != protoTCP {
		return
	}
	for _, g := range t.groups[:t.n] {
		if g.segs > 0 && g.sameFlow(pkt) {
			g.flush(p)
			return
		}
	}
}

// canAppend applies the merge rules against the group's first-segment header.
func (g *groGroup) canAppend(pkt []byte) bool {
	if g.closed {
		return false
	}
	payload := len(pkt) - 40
	if pkt[32]>>4 != 5 || g.buf[32]>>4 != 5 {
		// TCP options would have to be byte-identical to replicate on
		// re-segmentation; timestamps never are. Data-offset-5 only.
		return false
	}
	if payload > g.gsoSize || g.length+payload > groMaxLen {
		return false
	}
	if binary.BigEndian.Uint32(pkt[24:28]) != g.nextSeq {
		return false
	}
	if binary.BigEndian.Uint16(pkt[4:6]) != g.nextID {
		return false
	}
	// Header fields that must match the group's exactly: TOS/TTL, ack number,
	// window, urgent pointer, and flags apart from PSH/FIN (which fold in).
	if pkt[1] != g.buf[1] || pkt[8] != g.buf[8] {
		return false
	}
	if string(pkt[28:32]) != string(g.buf[28:32]) || // ack
		string(pkt[34:36]) != string(g.buf[34:36]) || // window
		string(pkt[38:40]) != string(g.buf[38:40]) { // urgent pointer
		return false
	}
	return pkt[33]&tcpFlagMask&^(tcpFlagPSH|tcpFlagFIN) == g.buf[33]&tcpFlagMask&^(tcpFlagPSH|tcpFlagFIN)
}

// start begins a group with pkt as its first segment. A data-offset other
// than 5 never gets here appended-to (canAppend refuses), so a group that
// starts with TCP options simply flushes as the single packet it is.
func (g *groGroup) start(pkt []byte) {
	g.buf = append(g.buf[:0], pkt...)
	g.length = len(pkt)
	g.segs = 1
	g.gsoSize = len(pkt) - 40
	g.nextSeq = binary.BigEndian.Uint32(pkt[24:28]) + uint32(g.gsoSize)
	g.nextID = binary.BigEndian.Uint16(pkt[4:6]) + 1
	g.closed = pkt[33]&(tcpFlagPSH|tcpFlagFIN) != 0 || pkt[32]>>4 != 5
}

// append adds pkt's payload to the group. A short segment, PSH, or FIN closes
// it, mirroring gso_size semantics on the way back out.
func (g *groGroup) append(pkt []byte) {
	payload := pkt[40:]
	g.buf = append(g.buf[:g.length], payload...)
	g.length += len(payload)
	g.segs++
	g.nextSeq += uint32(len(payload))
	g.nextID++
	if flags := pkt[33] & (tcpFlagPSH | tcpFlagFIN); flags != 0 {
		g.buf[33] |= flags
		g.closed = true
	}
	if len(payload) < g.gsoSize {
		g.closed = true
	}
}

// flush writes the group to the TUN. One segment goes out exactly as it
// arrived (its verified checksum intact); a coalesced frame gets its lengths
// and IP checksum rebuilt, the TCP checksum replaced by the pseudo-header sum,
// and a virtio-net header declaring TCPv4 GSO at the group's segment size.
func (g *groGroup) flush(p *Pump) {
	if g.segs == 0 {
		return
	}
	defer func() { g.segs, g.length = 0, 0 }()
	if g.segs == 1 {
		if _, err := p.writeTUN(g.buf[:g.length]); err != nil && p.log != nil {
			p.log.Warnf("dataplane: TUN write failed: %v", err)
		}
		return
	}
	frame := g.buf[:g.length]
	binary.BigEndian.PutUint16(frame[2:4], uint16(g.length))
	frame[10], frame[11] = 0, 0
	binary.BigEndian.PutUint16(frame[10:12], ^foldSum(onesComplementSum(0, frame[:20])))
	// CHECKSUM_PARTIAL: the checksum field holds the (uncomplemented)
	// pseudo-header sum; csum_start/csum_offset point the kernel at the rest.
	l4len := uint32(g.length - 20)
	acc := onesComplementSum(0, frame[12:20])
	acc += protoTCP + l4len
	binary.BigEndian.PutUint16(frame[36:38], foldSum(acc))

	hdr := p.gro.hdr[:]
	putVirtioNetHdr(hdr, virtioNetHdr{
		flags:      vnetFlagNeedsCsum,
		gsoType:    vnetGSOTCPv4,
		hdrLen:     40,
		gsoSize:    uint16(g.gsoSize),
		csumStart:  20,
		csumOffset: 16,
	})
	if _, err := p.vnetWriteGSO(hdr, frame); err != nil && p.log != nil {
		p.log.Warnf("dataplane: TUN GSO write failed: %v", err)
	}
}
