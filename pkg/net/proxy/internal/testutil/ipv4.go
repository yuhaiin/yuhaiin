package testutil

import (
	"encoding/binary"
	"errors"
	"net"
)

// IPv4UDP builds a minimal IPv4 packet carrying one UDP datagram.
func IPv4UDP(src, dst net.IP, srcPort, dstPort uint16, data []byte) []byte {
	packet := make([]byte, 28+len(data))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 17
	copy(packet[12:16], src.To4())
	copy(packet[16:20], dst.To4())
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], data)
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	return packet
}

// IPv4UDPData validates an IPv4 UDP packet and returns its payload.
func IPv4UDPData(packet []byte) ([]byte, error) {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 {
		return nil, errors.New("packet is not IPv4 UDP")
	}
	headerLen := int(packet[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLen < 20 || totalLen < headerLen+8 || totalLen > len(packet) {
		return nil, errors.New("invalid IPv4 UDP packet length")
	}
	udp := packet[headerLen:totalLen]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return nil, errors.New("invalid UDP packet length")
	}
	return udp[8:udpLen], nil
}

func checksum(header []byte) uint16 {
	var sum uint32
	for len(header) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(header))
		header = header[2:]
	}
	if len(header) == 1 {
		sum += uint32(header[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
