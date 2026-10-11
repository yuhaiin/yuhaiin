package dataplane

// Path MTU: telling the host when a packet will not fit.
//
// MTU black-holing is the most common real-world VPN failure, and it looks like
// nothing else: the tunnel comes up, small packets work, SSH works, and then a
// large HTTP response or a file transfer hangs forever. It happens because a
// tunnel's usable MTU is smaller than the interface the host is routing over,
// and nothing tells the host that.
//
// The host is willing to be told. TCP sets DF on everything, and a router that
// cannot forward a DF packet is required to answer with ICMP "fragmentation
// needed", carrying the MTU that *would* have worked. The sending stack lowers
// its path MTU for that destination and retransmits. That mechanism is why the
// internet works across links of differing MTU — a VPN that does not participate
// in it is the broken party.
//
// Before this, veepin silently dropped oversized packets. This makes it answer.
//
// Only the two message types that matter are implemented, by hand: encoding
// ICMPv3 fragmentation-needed and recognising one on the way back. That is a few
// dozen lines and keeps this consistent with the rest of the tree, where
// golang.org/x/net/icmp would have been the only reason to take a new dependency.

import (
	"encoding/binary"
	"net/netip"
)

// ICMP constants (RFC 792), and the IPv4 header fields this needs.
const (
	icmpTypeDestUnreachable = 3
	icmpCodeFragNeeded      = 4

	ipv4HeaderMin = 20
	ipv4FlagDF    = 0x40 // high bit of the flags/fragment-offset field
	protoICMP     = 1
)

// NeedsFragmentation reports whether an inner packet is too large for a tunnel
// of the given MTU and the sender must be told rather than the packet silently
// dropped. For IPv4 that means DF is set; for IPv6, every oversized packet
// qualifies, since IPv6 routers never fragment in transit — the host owns path
// MTU discovery (RFC 8200 §5).
//
// An IPv4 packet over the MTU *without* DF is a different case: the sender has
// permitted fragmentation, so dropping it is a plain loss rather than a
// black hole, and no notification is owed.
func NeedsFragmentation(pkt []byte, mtu int) bool {
	if len(pkt) <= mtu || len(pkt) < 1 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		return len(pkt) >= ipv4HeaderMin && pkt[6]&ipv4FlagDF != 0
	case 6:
		return len(pkt) >= IPv6HeaderLen
	default:
		return false
	}
}

// FragNeeded builds an ICMP "fragmentation needed" reply for a packet that will
// not fit, to be written back to the TUN so the local stack learns the path MTU.
//
// The reply is addressed from the packet's own destination, because that is who
// the sender believes it is talking to: an ICMP error from anywhere else is
// ignored, and rightly so. Returning it to the TUN rather than the network is
// what makes this work — the tunnel *is* the constrained hop.
//
// It returns nil if the input is not something an error can be built for. For an
// IPv6 packet it builds an ICMPv6 Packet Too Big instead (see fragNeededV6).
func FragNeeded(pkt []byte, mtu int) []byte {
	if len(pkt) >= 1 && pkt[0]>>4 == 6 {
		return fragNeededV6(pkt, mtu)
	}
	if len(pkt) < ipv4HeaderMin || pkt[0]>>4 != 4 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderMin || len(pkt) < ihl {
		return nil
	}

	// RFC 1812: the error carries the offending packet's header plus the first
	// 8 octets of its payload, which is what lets the sender match it to a
	// socket. More is permitted; this is the interoperable minimum.
	quote := min(ihl+8, len(pkt))

	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))

	icmpLen := 8 + quote
	out := make([]byte, ipv4HeaderMin+icmpLen)

	// Outer IPv4 header: from the original destination, back to the sender.
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[8] = 64 // TTL
	out[9] = protoICMP
	d, s := dst.As4(), src.As4()
	copy(out[12:16], d[:])
	copy(out[16:20], s[:])
	putIPv4Checksum(out[:ipv4HeaderMin])

	// ICMP destination unreachable / fragmentation needed.
	icmp := out[ipv4HeaderMin:]
	icmp[0] = icmpTypeDestUnreachable
	icmp[1] = icmpCodeFragNeeded
	// Bytes 4-5 are unused for this code; 6-7 carry the next-hop MTU, which is
	// the whole point of the message.
	binary.BigEndian.PutUint16(icmp[6:8], uint16(mtu))
	copy(icmp[8:], pkt[:quote])
	putICMPChecksum(icmp)

	return out
}

// ParseFragNeeded reports the next-hop MTU from an inbound ICMP
// fragmentation-needed message, if that is what the packet is.
//
// This is the other half: an outer datagram that is too large for some hop
// beyond the tunnel produces one of these from a router in the path, and it
// tells veepin to lower its own effective MTU rather than keep sending packets
// that cannot arrive.
func ParseFragNeeded(pkt []byte) (mtu int, ok bool) {
	if len(pkt) < ipv4HeaderMin || pkt[0]>>4 != 4 || pkt[9] != protoICMP {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderMin || len(pkt) < ihl+8 {
		return 0, false
	}
	icmp := pkt[ihl:]
	if icmp[0] != icmpTypeDestUnreachable || icmp[1] != icmpCodeFragNeeded {
		return 0, false
	}

	next := int(binary.BigEndian.Uint16(icmp[6:8]))
	if next == 0 {
		// A pre-RFC-1191 router reports no MTU. Nothing usable is being said,
		// so this is reported as "not a usable message" rather than as an MTU
		// of zero that a caller might act on.
		return 0, false
	}
	return next, true
}

// putIPv4Checksum computes and stores the header checksum in place.
func putIPv4Checksum(hdr []byte) {
	hdr[10], hdr[11] = 0, 0
	binary.BigEndian.PutUint16(hdr[10:12], onesComplement(hdr))
}

// putICMPChecksum computes and stores the ICMP checksum in place.
func putICMPChecksum(icmp []byte) {
	icmp[2], icmp[3] = 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], onesComplement(icmp))
}

// onesComplement is the internet checksum (RFC 1071) over a single buffer.
func onesComplement(b []byte) uint16 {
	return checksumFold(checksumAccumulate(0, b))
}

// checksumAccumulate adds b's 16-bit words to a running one's-complement sum,
// so a checksum can span several buffers (an IPv6 pseudo-header plus the ICMPv6
// message, for instance). An odd trailing byte is treated as the high octet of a
// final word, matching RFC 1071.
func checksumAccumulate(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// checksumFold collapses an accumulated sum to the final 16-bit checksum.
func checksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
