//go:build linux

package dataplane

// The GSO egress loop: doc/scaling-the-data-path.md's "TUN half".
//
// On a vnet TUN every read carries a virtio-net header and may be a TCP
// super-frame standing in for dozens of wire-sized packets. This loop cuts a
// super-frame into segments (offload_linux.go), routes once — every segment
// shares the inner destination — encapsulates each, and flushes the burst
// through the pump's batch sender (one sendmmsg) when the protocol registered
// one. That is the moment the two batching halves meet: one TUN read becomes
// one UDP syscall, instead of N reads and N sends.

// runVnet is Run for a GSO device. It blocks until the TUN is closed.
func (p *Pump) runVnet() {
	buf := make([]byte, virtioNetHdrLen+65535)
	var segs [][]byte             // segment scratch, reused across super-frames
	outs := make([][]byte, 0, 64) // encapsulated burst awaiting flush
	for {
		n, err := p.tun.Read(buf)
		if err != nil {
			if p.closing.Load() {
				return
			}
			if p.log != nil {
				p.log.Warnf("dataplane: TUN read error: %v", err)
			}
			return
		}
		if n < virtioNetHdrLen {
			continue
		}
		hdr := parseVirtioNetHdr(buf[:virtioNetHdrLen])
		pkt := buf[virtioNetHdrLen:n]

		switch hdr.gsoType {
		case vnetGSONone:
			// One ordinary packet — but TUN_F_CSUM means its transport
			// checksum may be partial, left for "the device" to finish.
			if hdr.flags&vnetFlagNeedsCsum != 0 {
				completePartialChecksum(pkt, int(hdr.csumStart), int(hdr.csumOffset))
			}
			p.routeOutbound(pkt)
		case vnetGSOTCPv4:
			nseg, err := segmentTSO4(pkt, hdr, &segs)
			if err != nil {
				if p.log != nil {
					p.log.Warnf("dataplane: dropping TSO super-frame: %v", err)
				}
				continue
			}
			outs = p.sendSegments(segs[:nseg], outs)
		default:
			// Not negotiated in TUNSETOFFLOAD (TSO6, USO, ECN), so the kernel
			// should never send it; drop rather than corrupt.
			if p.log != nil {
				p.log.Warnf("dataplane: dropping unnegotiated GSO type %#x", hdr.gsoType)
			}
		}
	}
}

// sendSegments routes one super-frame's segments — one lookup, they share a
// destination — encapsulates each, and flushes the burst: one batched send
// when the transport has one, per-packet sends otherwise. It returns outs
// reset to length zero so the caller keeps the burst's capacity.
func (p *Pump) sendSegments(segs [][]byte, outs [][]byte) [][]byte {
	dst, ok := innerDest(segs[0])
	if !ok {
		p.drops[DropNotIP].Add(1)
		return outs[:0]
	}
	b := p.tables.Load().routes.lookup(dst)
	t, c := b.t, b.c
	if t == nil {
		p.drops[DropNoRoute].Add(1)
		return outs[:0] // no tunnel carries this destination
	}

	// The kernel sizes segments to the interface MTU, but path MTU discovery
	// may have learned a smaller inner MTU. One fragmentation-needed answers
	// the whole super-frame — every segment is the same flow.
	mtu := p.innerMTU()
	if mtu > 0 && NeedsFragmentation(segs[0], mtu) {
		p.drops[DropTooBig].Add(uint64(len(segs)))
		if reply := FragNeeded(segs[0], mtu); reply != nil {
			if _, err := p.writeTUN(reply); err != nil && p.log != nil {
				p.log.Printf("dataplane: writing ICMP frag-needed: %v", err)
			}
		}
		return outs[:0]
	}

	// A paced tunnel sends on its own schedule, so a super-frame is handed to
	// it segment by segment exactly as routeOutbound hands it single packets.
	// This branch was missing: on a GSO TUN -- which every veepin client
	// negotiates -- bulk TCP went straight to the wire through the tunnel's
	// Encapsulate, beside the pacer rather than through it, so a
	// constant-rate IP-TFS tunnel sent its heaviest traffic at whatever rate
	// that traffic arrived. That is the very signal constant-rate transmission
	// exists to remove, leaking on exactly the flows that most reveal it.
	if pt := b.paced; pt != nil {
		for _, seg := range segs {
			if !pt.Enqueue(seg) {
				p.drops[DropPacerFull].Add(1)
				continue
			}
			c.countTx(len(seg))
		}
		return outs[:0]
	}

	outs = outs[:0]
	for i, seg := range segs {
		// Each segment gets its own slot -- the burst holds every output at
		// once until the flush, so one shared buffer would send the last
		// segment N times. Encapsulate's fresh buffers needed no slots; an
		// AppendTunnel's reused ones do.
		//
		// Shaping is naturally inert here: the kernel only hands up a TSO
		// super-frame for bulk transfer, and its segments already arrive at
		// the MTU. That is the right outcome — a super-frame is never a
		// handshake, so there is nothing for the shaper to hide.
		out, err := p.encap(b, seg, mtu, p.burstBuf(i))
		if err != nil {
			p.drops[DropEncapFailed].Add(1)
			if p.log != nil {
				p.log.Warnf("dataplane: encap failed: %v", err)
			}
			continue
		}
		// Per segment, not per super-frame: a TSO super-frame is several
		// packets on the wire, and counting it once would report a
		// GSO-enabled server as moving a fraction of what it moved.
		c.countTx(len(seg))
		outs = append(outs, out)
	}
	if len(outs) == 0 {
		return outs[:0]
	}
	if p.batchSend != nil {
		p.batchSend(outs, t.PeerAddr())
		return outs[:0]
	}
	for _, out := range outs {
		p.send(out, t.PeerAddr())
	}
	return outs[:0]
}
