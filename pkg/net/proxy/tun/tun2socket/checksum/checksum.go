package checksum

var ZeroChecksum = [2]byte{0x00, 0x00}

var sum = unrolledSumCompat

func Sum(b []byte) uint32 {
	return sum(b)
}

// Checksum for Internet Protocol family headers
func Checksum(sum uint32, b []byte) (answer [2]byte) {
	sum += Sum(b)
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	sum = ^sum
	answer[0] = byte(sum >> 8)
	answer[1] = byte(sum)
	return
}

func CheckSumCombine(sum uint32, b []byte) uint16 {
	if len(b) != 0 {
		sum += Sum(b)
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(sum)
}
