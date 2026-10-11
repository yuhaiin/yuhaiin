//go:build linux

package dataplane

// Userspace TSO: the virtio-net header and the TCP segmentation the TUN GSO
// path needs.
//
// With IFF_VNET_HDR + TUNSETOFFLOAD(TUN_F_CSUM|TUN_F_TSO4), the kernel's local
// stack may hand the TUN reader one TCP "super-frame" of up to 64 KB in place
// of dozens of MTU-sized packets — one read syscall, one route lookup — with a
// 10-byte virtio-net header describing how to cut it back into wire-sized
// segments. The cutting is this file: header replication, per-segment IP
// total-length/ID/TCP-sequence fixups, FIN/PSH only on the final segment, and
// full checksum computation (TUN_F_CSUM means the kernel also skips checksums,
// leaving the NIC-offload partial-checksum contract for us to complete).
//
// Scope is deliberately the tree's: IPv4 + TCP (TUN_F_TSO4). TSO6, UDP GSO
// (USO), and ECN segmentation are not negotiated in TUNSETOFFLOAD, so the
// kernel never sends them up.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// virtio_net_hdr (<linux/virtio_net.h>), the 10-byte prefix on every packet
// read from or written to a TUN opened with IFF_VNET_HDR. Fields are
// little-endian on every architecture this tree ships (amd64/arm64/armv7); the
// TUN default is guest-endian, which is the same thing there.
const (
	virtioNetHdrLen = 10

	vnetFlagNeedsCsum = 0x01 // csum_start/csum_offset describe a partial checksum

	vnetGSONone  = 0x00
	vnetGSOTCPv4 = 0x01
)

type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16 // bytes of packet headers (IP + transport)
	gsoSize    uint16 // payload bytes per segment
	csumStart  uint16
	csumOffset uint16
}

// putVirtioNetHdr encodes h into b, which must be at least virtioNetHdrLen.
func putVirtioNetHdr(b []byte, h virtioNetHdr) {
	b[0], b[1] = h.flags, h.gsoType
	binary.LittleEndian.PutUint16(b[2:4], h.hdrLen)
	binary.LittleEndian.PutUint16(b[4:6], h.gsoSize)
	binary.LittleEndian.PutUint16(b[6:8], h.csumStart)
	binary.LittleEndian.PutUint16(b[8:10], h.csumOffset)
}

func parseVirtioNetHdr(b []byte) virtioNetHdr {
	return virtioNetHdr{
		flags:      b[0],
		gsoType:    b[1],
		hdrLen:     binary.LittleEndian.Uint16(b[2:4]),
		gsoSize:    binary.LittleEndian.Uint16(b[4:6]),
		csumStart:  binary.LittleEndian.Uint16(b[6:8]),
		csumOffset: binary.LittleEndian.Uint16(b[8:10]),
	}
}

// onesComplementSum accumulates b into acc as big-endian 16-bit words
// (RFC 1071); a trailing odd byte is padded with zero.
func onesComplementSum(acc uint32, b []byte) uint32 {
	for ; len(b) >= 2; b = b[2:] {
		acc += uint32(b[0])<<8 | uint32(b[1])
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

// foldSum folds the carries and returns the 16-bit one's-complement sum
// (not yet complemented).
func foldSum(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return uint16(acc)
}

// completePartialChecksum finishes a CHECKSUM_PARTIAL packet exactly as NIC
// checksum offload would: the kernel has stored the pseudo-header sum at
// start+offset, and the device folds everything from start onward (that stored
// sum included) and writes the complement back at the offset. It is a no-op on
// offsets that do not fit the packet — a malformed descriptor is the kernel's
// bug, not a reason to corrupt memory.
func completePartialChecksum(pkt []byte, start, offset int) {
	if start < 0 || offset < 0 || start+offset+2 > len(pkt) {
		return
	}
	c := ^foldSum(onesComplementSum(0, pkt[start:]))
	binary.BigEndian.PutUint16(pkt[start+offset:], c)
}

const (
	protoTCP   = 6
	tcpFlagFIN = 0x01
	tcpFlagPSH = 0x08

	// maxTSOSegments bounds how many segments one super-frame may cut into.
	// 64 KB of payload at the smallest gso_size the kernel produces stays far
	// under this; anything past it is a malformed descriptor.
	maxTSOSegments = 256
)

var errTSOBounds = errors.New("dataplane: TSO super-frame out of bounds")

// segmentTSO4 cuts an IPv4/TCP super-frame (without its virtio-net header)
// into wire-sized segments of at most hdr.gsoSize payload bytes each. Segment i
// is written into (*segs)[i], which is grown and resized as needed and reused
// across calls, so a steady-state caller allocates nothing. It returns the
// number of segments produced.
//
// Each segment gets the super-frame's headers with the per-segment fixups TSO
// hardware would do: IP total length, IP ID incrementing from the original,
// TCP sequence advanced by the payload offset, FIN/PSH kept only on the final
// segment, and freshly computed IP and TCP checksums (the input's checksums
// are partial — TUN_F_CSUM — and are not trusted).
func segmentTSO4(pkt []byte, hdr virtioNetHdr, segs *[][]byte) (int, error) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, errors.New("dataplane: TSO super-frame is not IPv4")
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return 0, errTSOBounds
	}
	if pkt[9] != protoTCP {
		return 0, fmt.Errorf("dataplane: TSO super-frame carries protocol %d, not TCP", pkt[9])
	}
	thl := int(pkt[ihl+12]>>4) * 4
	if thl < 20 || len(pkt) < ihl+thl {
		return 0, errTSOBounds
	}
	hdrsLen := ihl + thl
	payload := pkt[hdrsLen:]
	gso := int(hdr.gsoSize)
	if gso <= 0 || len(payload) == 0 {
		return 0, errTSOBounds
	}
	nseg := (len(payload) + gso - 1) / gso
	if nseg > maxTSOSegments {
		return 0, errTSOBounds
	}

	baseID := binary.BigEndian.Uint16(pkt[4:6])
	baseSeq := binary.BigEndian.Uint32(pkt[ihl+4 : ihl+8])

	for len(*segs) < nseg {
		*segs = append(*segs, nil)
	}
	for i := range nseg {
		off := i * gso
		chunk := min(gso, len(payload)-off)
		segLen := hdrsLen + chunk
		if cap((*segs)[i]) < segLen {
			(*segs)[i] = make([]byte, segLen)
		}
		seg := (*segs)[i][:segLen]
		copy(seg, pkt[:hdrsLen])
		copy(seg[hdrsLen:], payload[off:off+chunk])

		binary.BigEndian.PutUint16(seg[2:4], uint16(segLen))
		binary.BigEndian.PutUint16(seg[4:6], baseID+uint16(i))
		binary.BigEndian.PutUint32(seg[ihl+4:ihl+8], baseSeq+uint32(off))
		if i != nseg-1 {
			seg[ihl+13] &^= tcpFlagFIN | tcpFlagPSH
		}

		// IP header checksum, over the header with its checksum field zeroed.
		seg[10], seg[11] = 0, 0
		binary.BigEndian.PutUint16(seg[10:12], ^foldSum(onesComplementSum(0, seg[:ihl])))

		// TCP checksum: pseudo-header (addresses, protocol, TCP length) plus
		// the TCP segment with its checksum field zeroed.
		seg[ihl+16], seg[ihl+17] = 0, 0
		acc := onesComplementSum(0, seg[12:20])
		acc += protoTCP + uint32(segLen-ihl)
		acc = onesComplementSum(acc, seg[ihl:])
		binary.BigEndian.PutUint16(seg[ihl+16:ihl+18], ^foldSum(acc))

		(*segs)[i] = seg
	}
	return nseg, nil
}
