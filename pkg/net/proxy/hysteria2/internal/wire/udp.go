package wire

import (
	"encoding/binary"
	"fmt"
	"time"
)

// UDPMessage is one Hysteria 2 QUIC DATAGRAM. Data aliases the input when
// decoded; callers must not recycle the backing buffer before consuming it.
type UDPMessage struct {
	SessionID     uint32
	PacketID      uint16
	FragmentID    uint8
	FragmentCount uint8
	Address       string
	Data          []byte
}

func (m UDPMessage) HeaderSize() int {
	n, _ := varintLen(uint64(len(m.Address)))
	return 8 + n + len(m.Address)
}

func (m UDPMessage) Size() int { return m.HeaderSize() + len(m.Data) }

func (m UDPMessage) validate() error {
	if len(m.Address) == 0 || len(m.Address) > MaxAddress || len(m.Data) == 0 {
		return fmt.Errorf("%w: invalid UDP address or payload", ErrMalformed)
	}
	if m.FragmentCount == 0 || m.FragmentID >= m.FragmentCount {
		return fmt.Errorf("%w: invalid fragmentation fields", ErrMalformed)
	}
	if m.Size() > MaxPacket {
		return fmt.Errorf("%w: UDP packet exceeds maximum size", ErrMalformed)
	}
	return nil
}

// AppendUDPMessage encodes into a caller-owned buffer. This is allocation free
// when dst has sufficient capacity. It does not silently truncate messages.
func AppendUDPMessage(dst []byte, m UDPMessage) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	start := len(dst)
	dst = append(dst, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(dst[start:], m.SessionID)
	binary.BigEndian.PutUint16(dst[start+4:], m.PacketID)
	dst[start+6], dst[start+7] = m.FragmentID, m.FragmentCount
	dst = appendVarint(dst, uint64(len(m.Address)))
	dst = append(dst, m.Address...)
	dst = append(dst, m.Data...)
	return dst, nil
}

func ParseUDPMessage(b []byte) (UDPMessage, error) {
	if len(b) < 10 {
		return UDPMessage{}, fmt.Errorf("%w: short UDP datagram", ErrMalformed)
	}
	n, consumed, err := readVarintBytes(b[8:])
	if err != nil {
		return UDPMessage{}, err
	}
	offset := 8 + consumed
	if n == 0 || n > MaxAddress || n >= uint64(len(b)-offset) {
		return UDPMessage{}, fmt.Errorf("%w: invalid UDP address length", ErrMalformed)
	}
	m := UDPMessage{
		SessionID:  binary.BigEndian.Uint32(b),
		PacketID:   binary.BigEndian.Uint16(b[4:]),
		FragmentID: b[6], FragmentCount: b[7],
		Address: string(b[offset : offset+int(n)]), Data: b[offset+int(n):],
	}
	if err := m.validate(); err != nil {
		return UDPMessage{}, err
	}
	return m, nil
}

// FragmentUDPMessage splits a datagram at the maximum QUIC payload size.
// PacketID must be unique per fragmented message in a session. The caller
// must not mutate Data before all fragment writes complete.
func FragmentUDPMessage(m UDPMessage, maxDatagram int) ([]UDPMessage, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	if maxDatagram <= m.HeaderSize() {
		return nil, fmt.Errorf("%w: MTU smaller than header", ErrMalformed)
	}
	if m.Size() <= maxDatagram {
		return []UDPMessage{m}, nil
	}
	if m.FragmentCount != 1 || m.FragmentID != 0 || m.PacketID == 0 {
		return nil, fmt.Errorf("%w: fragmented packets need fresh nonzero packet ID", ErrMalformed)
	}
	maxPayload := maxDatagram - m.HeaderSize()
	count := (len(m.Data) + maxPayload - 1) / maxPayload
	if count > 255 {
		return nil, fmt.Errorf("%w: too many UDP fragments", ErrMalformed)
	}
	result := make([]UDPMessage, 0, count)
	for off := 0; off < len(m.Data); off += maxPayload {
		end := min(off+maxPayload, len(m.Data))
		fragment := m
		fragment.FragmentID = uint8(len(result))
		fragment.FragmentCount = uint8(count)
		fragment.Data = m.Data[off:end]
		result = append(result, fragment)
	}
	return result, nil
}

// Defragger accepts at most one fragmented packet per UDP session.
// Expiration and an upper bound on reassembled size keep malicious clients
// from retaining unbounded memory. Not safe for concurrent Feed calls.
type Defragger struct {
	packet  uint16
	address string
	count   uint8
	size    int
	parts   [][]byte
	started time.Time
}

const FragmentTimeout = 5 * time.Second

func (d *Defragger) Reset() {
	d.packet = 0
	d.address = ""
	d.count = 0
	d.size = 0
	d.parts = nil
	d.started = time.Time{}
}

func (d *Defragger) Feed(m UDPMessage, now time.Time) (UDPMessage, bool, error) {
	if err := m.validate(); err != nil {
		return UDPMessage{}, false, err
	}
	if m.FragmentCount == 1 {
		return m, true, nil
	}
	if m.PacketID == 0 {
		return UDPMessage{}, false, fmt.Errorf("%w: fragmented packet with zero ID", ErrMalformed)
	}
	if len(d.parts) == 0 || d.packet != m.PacketID ||
		d.count != m.FragmentCount || d.address != m.Address ||
		now.Sub(d.started) >= FragmentTimeout || now.Before(d.started) {
		d.Reset()
		d.packet, d.address, d.count, d.started = m.PacketID, m.Address, m.FragmentCount, now
		d.parts = make([][]byte, int(m.FragmentCount))
	}
	if d.parts[m.FragmentID] != nil {
		if !equalBytes(d.parts[m.FragmentID], m.Data) {
			d.Reset()
			return UDPMessage{}, false, fmt.Errorf("%w: conflicting duplicate fragment", ErrMalformed)
		}
		return UDPMessage{}, false, nil
	}
	if d.size+len(m.Data) > MaxPacket {
		d.Reset()
		return UDPMessage{}, false, fmt.Errorf("%w: oversized reassembly", ErrMalformed)
	}
	d.parts[m.FragmentID] = append([]byte(nil), m.Data...)
	d.size += len(m.Data)
	for _, part := range d.parts {
		if part == nil {
			return UDPMessage{}, false, nil
		}
	}
	payload := make([]byte, 0, d.size)
	for _, part := range d.parts {
		payload = append(payload, part...)
	}
	d.Reset()
	m.Data, m.FragmentID, m.FragmentCount = payload, 0, 1
	return m, true, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}
