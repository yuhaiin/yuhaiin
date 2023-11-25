package checksum

// sumCompat calculates the checksum (as defined in RFC 1071) of the bytes in
// the given byte array. This function uses a non-optimized implementation. Its
// only retained for reference and to use as a benchmark/test. Most code should
// use the unrolledSumCompat function.
func sumCompat(b []byte) (sum uint32) {
	n := len(b)
	if n&1 != 0 {
		n--
		sum += uint32(b[n]) << 8
	}

	// the sum of each 16 bit value
	for i := 0; i < n; i += 2 {
		sum += (uint32(b[i]) << 8) | uint32(b[i+1])
	}
	return
}

// unrolledSumCompat calculates the checksum (as defined in RFC 1071) of the bytes in the
// given byte array. This function uses an optimized unrolled version of the
// checksum algorithm.
func unrolledSumCompat(buf []byte) (v uint32) {
	l := len(buf)
	if l&1 != 0 {
		l--
		v += uint32(buf[l]) << 8
	}

	for (l - 64) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		i += 16
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		i += 16
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		i += 16
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		buf = buf[64:]
		l = l - 64
	}

	if (l - 32) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		i += 16
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		buf = buf[32:]
		l = l - 32
	}

	if (l - 16) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		v += (uint32(buf[i+8]) << 8) + uint32(buf[i+9])
		v += (uint32(buf[i+10]) << 8) + uint32(buf[i+11])
		v += (uint32(buf[i+12]) << 8) + uint32(buf[i+13])
		v += (uint32(buf[i+14]) << 8) + uint32(buf[i+15])
		buf = buf[16:]
		l = l - 16
	}
	if (l - 8) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		v += (uint32(buf[i+4]) << 8) + uint32(buf[i+5])
		v += (uint32(buf[i+6]) << 8) + uint32(buf[i+7])
		buf = buf[8:]
		l = l - 8
	}
	if (l - 4) >= 0 {
		i := 0
		v += (uint32(buf[i]) << 8) + uint32(buf[i+1])
		v += (uint32(buf[i+2]) << 8) + uint32(buf[i+3])
		buf = buf[4:]
		l = l - 4
	}

	// At this point since l was even before we started unrolling
	// there can be only two bytes left to add.
	if l != 0 {
		v += (uint32(buf[0]) << 8) + uint32(buf[1])
	}

	return v
}
