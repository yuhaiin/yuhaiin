package lightweight

import (
	"encoding/binary"
	"net/netip"
)

// Checksum returns the Internet checksum, including an odd trailing octet.
func Checksum(b []byte) uint16 {
	if checksumAccelerated && len(b) >= 128 {
		return ^fold(sumBytes(b, 0))
	}
	return ^fold(sumBytesGeneric(b, 0))
}

func sumBytes(b []byte, sum uint32) uint32 {
	if checksumAccelerated && len(b) >= 128 {
		b, sum = checksumBulk(b, sum)
	}
	return sumBytesGeneric(b, sum)
}
func sumBytesGeneric(b []byte, sum uint32) uint32 {
	// Portable small-packet and tail loop, also used for the entire input on
	// other architectures. Folding each block bounds accumulation.
	for len(b) >= 16 {
		a := binary.BigEndian.Uint32(b[:4])
		c := binary.BigEndian.Uint32(b[4:8])
		d := binary.BigEndian.Uint32(b[8:12])
		e := binary.BigEndian.Uint32(b[12:16])
		sum = sum&65535 + sum>>16
		sum += a>>16 + a&65535 + c>>16 + c&65535 + d>>16 + d&65535 + e>>16 + e&65535
		b = b[16:]
	}
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	return sum
}
func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return uint16(sum)
}
func transportChecksum(src, dst netip.Addr, proto uint8, b []byte) uint16 {
	sum := pseudoHeaderSum(src, dst, proto, len(b))
	if checksumAccelerated && len(b) >= 128 {
		return ^fold(sumBytes(b, sum))
	}
	return ^fold(sumBytesGeneric(b, sum))
}
func pseudoHeaderSum(src, dst netip.Addr, proto uint8, length int) uint32 {
	// Addresses and packet headers must retain the leaf Go path: GSO eliminates
	// payload checksumming, leaving many tiny ACK/header calls in the hot path.
	sum := sumBytesGeneric(src.AsSlice(), 0)
	sum = sumBytesGeneric(dst.AsSlice(), sum)
	return sum + uint32(proto) + uint32(length&65535) + uint32(length>>16)
}
