package ike

import (
	"crypto/sha1"
	"encoding/binary"
	"net"
)

// natDetectionHash computes SHA1(SPIi | SPIr | IP | Port), the value carried in
// NAT_DETECTION_SOURCE_IP and NAT_DETECTION_DESTINATION_IP notifies
// (RFC 7296 section 2.23). SPIs are the IKE SPIs in wire (big-endian) order.
func natDetectionHash(spiI, spiR uint64, ip net.IP, port uint16) []byte {
	h := sha1.New()
	var spi [8]byte
	binary.BigEndian.PutUint64(spi[:], spiI)
	h.Write(spi[:])
	binary.BigEndian.PutUint64(spi[:], spiR)
	h.Write(spi[:])
	if v4 := ip.To4(); v4 != nil {
		h.Write(v4)
	} else {
		h.Write(ip.To16())
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	h.Write(p[:])
	return h.Sum(nil)
}

// natInfo records what NAT detection concluded for a session.
type natInfo struct {
	// peerBehindNAT is true if the source-IP hash the peer sent does not match
	// what we observed, i.e. the initiator is behind NAT.
	peerBehindNAT bool
	// weAreBehindNAT is true if the destination-IP hash the peer sent does not
	// match our own address, i.e. the responder is behind NAT.
	weAreBehindNAT bool
}

// natDetected reports whether either endpoint is behind NAT, meaning ESP must
// be UDP-encapsulated on port 4500.
func (n natInfo) natDetected() bool {
	return n.peerBehindNAT || n.weAreBehindNAT
}
