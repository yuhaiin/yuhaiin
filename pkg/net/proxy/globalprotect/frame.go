package globalprotect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	frameHeaderSize = 16
	maxFramePayload = 65535
	etherIPv4       = 0x0800
	etherIPv6       = 0x86dd
)

// GlobalProtect SSL tunnel frames are magic|ethertype|length|reserved|packet.
// A frame with ethertype 0 is a DPD ping/response and is not passed to gVisor.
var magic = [4]byte{0x1a, 0x2b, 0x3c, 0x4d}

func encodeFrame(packet []byte) ([]byte, error) {
	if len(packet) == 0 || len(packet) > maxFramePayload {
		return nil, fmt.Errorf("globalprotect: invalid packet length %d", len(packet))
	}
	eth := uint16(0)
	switch packet[0] >> 4 {
	case 4:
		eth = etherIPv4
	case 6:
		eth = etherIPv6
	default:
		return nil, errors.New("globalprotect: only IPv4/IPv6 packets are supported")
	}
	frame := make([]byte, frameHeaderSize+len(packet))
	copy(frame, magic[:])
	binary.BigEndian.PutUint16(frame[4:6], eth)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(packet)))
	frame[8] = 1
	copy(frame[frameHeaderSize:], packet)
	return frame, nil
}

func dpdFrame() []byte {
	frame := make([]byte, frameHeaderSize)
	copy(frame, magic[:])
	return frame
}

func readFrame(r io.Reader) (payload []byte, keepalive bool, err error) {
	var h [frameHeaderSize]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return nil, false, err
	}
	if !bytes.Equal(h[:4], magic[:]) {
		return nil, false, errors.New("globalprotect: invalid SSL frame magic")
	}
	n := int(binary.BigEndian.Uint16(h[6:8]))
	eth := binary.BigEndian.Uint16(h[4:6])
	if eth == 0 {
		if n > 0 {
			if _, err = io.CopyN(io.Discard, r, int64(n)); err != nil {
				return nil, false, err
			}
		}
		return nil, true, nil
	}
	if eth != etherIPv4 && eth != etherIPv6 {
		return nil, false, errors.New("globalprotect: unsupported ethertype")
	}
	if n == 0 {
		return nil, false, errors.New("globalprotect: empty IP frame")
	}
	// The gateway may send packets larger than the negotiated MTU, and some
	// appliances use non-standard reserved flag bytes. The uint16 frame length
	// still bounds allocations to 65535 bytes.
	packet := make([]byte, n)
	if _, err = io.ReadFull(r, packet); err != nil {
		return nil, false, err
	}
	if (packet[0]>>4) != 4 && (packet[0]>>4) != 6 {
		return nil, false, errors.New("globalprotect: invalid IP version")
	}
	if (packet[0]>>4) == 4 && eth != etherIPv4 || (packet[0]>>4) == 6 && eth != etherIPv6 {
		return nil, false, errors.New("globalprotect: IP version mismatch")
	}
	return packet, false, nil
}
