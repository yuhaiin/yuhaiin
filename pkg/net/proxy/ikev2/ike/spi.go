package ike

import (
	"crypto/rand"
	"encoding/binary"
)

// newIKESPI returns a random non-zero 8-octet IKE SPI.
func newIKESPI() uint64 {
	var b [8]byte
	for {
		_, _ = rand.Read(b[:])
		v := binary.BigEndian.Uint64(b[:])
		if v != 0 {
			return v
		}
	}
}

// newChildSPI returns a random non-zero 4-octet ESP SPI.
func newChildSPI() uint32 {
	var b [4]byte
	for {
		_, _ = rand.Read(b[:])
		v := binary.BigEndian.Uint32(b[:])
		if v != 0 {
			return v
		}
	}
}
