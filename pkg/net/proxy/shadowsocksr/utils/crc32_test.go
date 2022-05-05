package ssr

import (
	"hash/crc32"
	"testing"
)

func TestXxx(t *testing.T) {
	t.Log(CalcCRC32([]byte{0x01, 0x02, 0x03, 0x04}, 4), crc32.ChecksumIEEE([]byte{0x01, 0x02, 0x03, 0x04}))
}
