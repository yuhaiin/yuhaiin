package tcpip

import (
	"encoding/binary"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/tun2socket/tcpip/checksum"
)

const (
	TCPFin uint16 = 1 << 0
	TCPSyn uint16 = 1 << 1
	TCPRst uint16 = 1 << 2
	TCPPuh uint16 = 1 << 3
	TCPAck uint16 = 1 << 4
	TCPUrg uint16 = 1 << 5
	TCPEce uint16 = 1 << 6
	TCPEwr uint16 = 1 << 7
	TCPNs  uint16 = 1 << 8
)

const TCPHeaderSize = 20

type TCPPacket []byte

func (p TCPPacket) SourcePort() uint16 {
	return binary.BigEndian.Uint16(p)
}

func (p TCPPacket) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(p, port)
}

func (p TCPPacket) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(p[2:])
}

func (p TCPPacket) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(p[2:], port)
}

func (p TCPPacket) Flags() uint16 {
	return uint16(p[13] | (p[12] & 0x1))
}

func (p TCPPacket) Checksum() uint16 {
	return binary.BigEndian.Uint16(p[16:])
}

func (p TCPPacket) SetChecksum(sum [2]byte) {
	p[16] = sum[0]
	p[17] = sum[1]
}

func (p TCPPacket) ResetChecksum(psum uint32) {
	p.SetChecksum(checksum.ZeroChecksum)
	p.SetChecksum(checksum.Checksum(psum, p))
}

func (p TCPPacket) Valid() bool {
	return len(p) >= TCPHeaderSize
}

func IsIPv4(packet []byte) bool {
	return len(packet) > 0 && (packet[0]>>4) == 4
}

func SetIPv4(packet []byte) {
	packet[0] = (packet[0] & 0x0f) | (4 << 4)
}
