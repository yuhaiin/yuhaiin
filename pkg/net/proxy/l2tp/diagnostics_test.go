package l2tp

import (
	"encoding/binary"
	"testing"
)

// Header-only ring buffer must discard payload bytes, retain temporal order
// across wrapping, and remain safe for repeated concurrent snapshots.
func TestTCPPacketTraceBoundedAndHeaderOnly(t *testing.T) {
	trace := newTCPPacketTrace(2)
	packet := make([]byte, 45)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 6
	copy(packet[12:16], []byte{192, 0, 2, 1})
	copy(packet[16:20], []byte{192, 0, 2, 2})
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum >> 16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], 19991)
	packet[32], packet[33] = 5<<4, 0x18
	copy(packet[40:], []byte("hello"))
	for i := uint32(1); i <= 3; i++ {
		binary.BigEndian.PutUint32(packet[24:28], i)
		trace.record("stack_to_l2tp", packet)
	}
	got := trace.snapshot()
	if len(got) != 2 || got[0].Seq != 2 || got[1].Seq != 3 {
		t.Fatalf("ring order: %+v", got)
	}
	if got[0].PayloadLen != 5 || got[0].Source != "192.0.2.1:40000" ||
		got[0].Dest != "192.0.2.2:19991" {
		t.Fatalf("TCP header fields: %+v", got[0])
	}
	packet[0] = 0 // Invalid packet: must not modify the ring.
	trace.record("l2tp_to_stack", packet)
	if next := trace.snapshot(); len(next) != 2 || next[0].Seq != 2 {
		t.Fatalf("invalid packet changed ring: %+v", next)
	}
}
