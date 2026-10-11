package dataplane

// The IPv6 half of path MTU discovery: ICMPv6 Packet Too Big.
//
// IPv6 has no in-network fragmentation and no DF bit — a router that cannot
// forward an oversized packet drops it and returns ICMPv6 Packet Too Big (type
// 2), carrying the MTU that would have worked, exactly the role ICMPv4
// fragmentation-needed plays for IPv4. The tunnel is the constrained hop, so
// veepin writes the error back to the TUN and the local stack lowers its path
// MTU for that destination.
//
// This is the same hand-rolled approach as icmp.go, for the same reason: a few
// dozen lines instead of a dependency on golang.org/x/net/icmp. The one wrinkle
// over ICMPv4 is the checksum, which for ICMPv6 covers an IPv6 pseudo-header.

import "encoding/binary"

const (
	icmp6TypePacketTooBig = 2
	protoICMPv6           = 58 // next-header value for ICMPv6
)

// fragNeededV6 builds an ICMPv6 Packet Too Big for an inner IPv6 packet that
// will not fit a tunnel of mtu octets, to be written back to the TUN. It returns
// nil if pkt is not a well-formed IPv6 header.
//
// The advertised MTU is never lowered below the IPv6 minimum link MTU (1280,
// RFC 8200 §5); a host must not shrink its path MTU below that floor.
func fragNeededV6(pkt []byte, mtu int) []byte {
	if len(pkt) < IPv6HeaderLen || pkt[0]>>4 != 6 {
		return nil
	}
	if mtu < MinIPv6MTU {
		mtu = MinIPv6MTU
	}

	// RFC 4443 §3.2: the message body is as much of the invoking packet as fits
	// without the ICMPv6 datagram exceeding the IPv6 minimum MTU.
	const maxReply = MinIPv6MTU
	quote := len(pkt)
	if q := maxReply - IPv6HeaderLen - 8; quote > q {
		quote = q
	}

	src := pkt[8:24]  // original source address
	dst := pkt[24:40] // original destination address

	icmpLen := 8 + quote
	out := make([]byte, IPv6HeaderLen+icmpLen)

	// Outer IPv6 header: from the original destination, back to the sender.
	out[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(out[4:6], uint16(icmpLen))
	out[6] = protoICMPv6 // next header
	out[7] = 64          // hop limit
	copy(out[8:24], dst) // src = original dst
	copy(out[24:40], src)

	// ICMPv6 Packet Too Big.
	icmp := out[IPv6HeaderLen:]
	icmp[0] = icmp6TypePacketTooBig
	icmp[1] = 0
	// Bytes 4-7 carry the MTU that would have worked.
	binary.BigEndian.PutUint32(icmp[4:8], uint32(mtu))
	copy(icmp[8:], pkt[:quote])
	putICMPv6Checksum(out[8:24], out[24:40], icmp)

	return out
}

// putICMPv6Checksum computes and stores the ICMPv6 checksum in place. Unlike
// ICMPv4, the sum covers an IPv6 pseudo-header (RFC 4443 §2.3): source and
// destination addresses, the ICMPv6 length as a 32-bit field, and the next-header
// value (58) in the low octet of a 32-bit field.
func putICMPv6Checksum(src, dst, icmp []byte) {
	icmp[2], icmp[3] = 0, 0

	var pseudo [40]byte
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = protoICMPv6

	sum := checksumAccumulate(0, pseudo[:])
	sum = checksumAccumulate(sum, icmp)
	binary.BigEndian.PutUint16(icmp[2:4], checksumFold(sum))
}
