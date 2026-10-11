// Adapted from xen0bit/veepin (MIT). See ../THIRD_PARTY_LICENSE.
package wire

import (
	"bytes"
	"testing"
)

func TestOpcodeRoundTrip(t *testing.T) {
	for _, keyID := range []uint8{0, 1, 7} {
		b := firstByte(PControlV1, keyID)
		op, k, ok := Opcode([]byte{b})
		if !ok || op != PControlV1 || k != keyID {
			t.Errorf("firstByte/Opcode(%d,%d) => op=%d key=%d ok=%v", PControlV1, keyID, op, k, ok)
		}
	}
	if _, _, ok := Opcode(nil); ok {
		t.Error("Opcode of empty packet reported ok")
	}
}

func TestIsControl(t *testing.T) {
	control := []uint8{PControlV1, PACKV1, PControlHardResetClientV2, PControlHardResetServerV2, PControlSoftResetV1}
	for _, op := range control {
		if !IsControl(op) {
			t.Errorf("opcode %d should be control", op)
		}
	}
	for _, op := range []uint8{PDataV1, PDataV2, 0, 31} {
		if IsControl(op) {
			t.Errorf("opcode %d should not be control", op)
		}
	}
}

// TestHardResetRoundTrip covers a client hard reset: session id, no acks, a
// packet id, and an empty payload.
func TestHardResetRoundTrip(t *testing.T) {
	p := &ControlPacket{
		Opcode:    PControlHardResetClientV2,
		KeyID:     0,
		SessionID: SessionID{1, 2, 3, 4, 5, 6, 7, 8},
		PacketID:  0,
	}
	buf := make([]byte, p.MarshalLen())
	out, err := p.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseControl(out)
	if err != nil {
		t.Fatal(err)
	}
	if got.Opcode != p.Opcode || got.SessionID != p.SessionID || got.PacketID != 0 {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if len(got.ACKs) != 0 {
		t.Errorf("unexpected acks: %v", got.ACKs)
	}
	if len(got.Payload) != 0 {
		t.Errorf("unexpected payload: %v", got.Payload)
	}
}

// TestControlWithACKsAndPayload covers a PControlV1 that both acknowledges
// earlier messages (so it carries a remote session id) and delivers TLS bytes.
func TestControlWithACKsAndPayload(t *testing.T) {
	p := &ControlPacket{
		Opcode:          PControlV1,
		KeyID:           1,
		SessionID:       SessionID{9, 9, 9, 9, 9, 9, 9, 9},
		ACKs:            []uint32{1, 2, 5},
		RemoteSessionID: SessionID{8, 7, 6, 5, 4, 3, 2, 1},
		PacketID:        42,
		Payload:         []byte("tls-handshake-bytes"),
	}
	buf := make([]byte, p.MarshalLen())
	out, err := p.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseControl(out)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != 1 || got.SessionID != p.SessionID || got.RemoteSessionID != p.RemoteSessionID {
		t.Errorf("ids mismatch: %+v", got)
	}
	if got.PacketID != 42 {
		t.Errorf("packet id = %d, want 42", got.PacketID)
	}
	if len(got.ACKs) != 3 || got.ACKs[0] != 1 || got.ACKs[2] != 5 {
		t.Errorf("acks = %v, want [1 2 5]", got.ACKs)
	}
	if !bytes.Equal(got.Payload, p.Payload) {
		t.Errorf("payload = %q, want %q", got.Payload, p.Payload)
	}
}

// TestACKPacketHasNoBody checks that a pure ACK encodes its acknowledgements but
// no message packet id or payload, and that parsing does not invent one.
func TestACKPacketHasNoBody(t *testing.T) {
	p := &ControlPacket{
		Opcode:          PACKV1,
		SessionID:       SessionID{1, 1, 1, 1, 1, 1, 1, 1},
		ACKs:            []uint32{7},
		RemoteSessionID: SessionID{2, 2, 2, 2, 2, 2, 2, 2},
		// PacketID and Payload set but must be dropped on the wire.
		PacketID: 99,
		Payload:  []byte("should not be encoded"),
	}
	buf := make([]byte, p.MarshalLen())
	out, err := p.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	// 1 opcode + 8 session + 1 ack-len + 4 ack + 8 remote session = 22.
	if len(out) != 22 {
		t.Fatalf("ack packet len = %d, want 22 (no body)", len(out))
	}
	got, err := ParseControl(out)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketID != 0 || len(got.Payload) != 0 {
		t.Errorf("ack packet carried a body: id=%d payload=%q", got.PacketID, got.Payload)
	}
	if len(got.ACKs) != 1 || got.ACKs[0] != 7 {
		t.Errorf("acks = %v, want [7]", got.ACKs)
	}
}

func TestParseControlRejects(t *testing.T) {
	// A data opcode is not a control packet.
	if _, err := ParseControl([]byte{firstByte(PDataV2, 0), 0, 0}); err == nil {
		t.Error("parsed a data packet as control")
	}
	// Truncated before the session id completes.
	if _, err := ParseControl([]byte{firstByte(PControlV1, 0), 1, 2, 3}); err == nil {
		t.Error("parsed a truncated packet")
	}
	// An ack count that runs off the end of the buffer.
	pkt := []byte{firstByte(PACKV1, 0)}
	pkt = append(pkt, make([]byte, SessionIDLen)...)
	pkt = append(pkt, 3) // claims 3 acks but supplies none
	if _, err := ParseControl(pkt); err == nil {
		t.Error("parsed an ack array past the buffer")
	}
}

func TestMarshalShortBuffer(t *testing.T) {
	p := &ControlPacket{Opcode: PControlHardResetClientV2}
	if _, err := p.Marshal(make([]byte, 3)); err != ErrShort {
		t.Errorf("Marshal into short buffer = %v, want ErrShort", err)
	}
}
