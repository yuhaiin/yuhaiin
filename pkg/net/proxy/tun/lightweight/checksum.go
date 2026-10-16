package lightweight

import "net/netip"

// Checksum returns the Internet checksum, including an odd trailing octet.
func Checksum(b []byte) uint16 { return ^fold(sumBytes(b, 0)) }
func sumBytes(b []byte, sum uint32) uint32 {
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
	sum := sumBytes(src.AsSlice(), 0)
	sum = sumBytes(dst.AsSlice(), sum)
	sum += uint32(proto) + uint32(len(b)&65535) + uint32(len(b)>>16)
	return ^fold(sumBytes(b, sum))
}
