package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestQUICVarints(t *testing.T) {
	for _, n := range []uint64{0, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1} {
		b := appendVarint(nil, n)
		if got, _, err := readVarintBytes(b); err != nil || got != n {
			t.Fatalf("%d: bytes got %d, %v", n, got, err)
		}
		if got, err := readVarint(bytes.NewReader(b)); err != nil || got != n {
			t.Fatalf("%d: reader got %d, %v", n, got, err)
		}
	}
	for _, b := range [][]byte{{0x40}, {0x80, 0x00}, {0xc0, 0x00}} {
		if _, _, err := readVarintBytes(b); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("accepted short varint: %x", b)
		}
	}
}

func TestTCPRoundTrip(t *testing.T) {
	const address = "example.org:443"
	var req bytes.Buffer
	if err := WriteTCPRequest(&req, address); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTCPRequest(&req)
	if err != nil || got != address {
		t.Fatalf("request %q, %v", got, err)
	}
	for _, ok := range []bool{false, true} {
		var resp bytes.Buffer
		if err := WriteTCPResponse(&resp, ok, "Connected"); err != nil {
			t.Fatal(err)
		}
		isOK, message, err := ReadTCPResponse(&resp)
		if err != nil || isOK != ok || message != "Connected" {
			t.Fatalf("response %v, %q, %v", isOK, message, err)
		}
	}
}

func TestTCPRejectsMalformed(t *testing.T) {
	if err := WriteTCPRequest(io.Discard, strings.Repeat("x", MaxAddress+1)); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	if _, err := ReadTCPRequest(bytes.NewReader(appendVarint(nil, 0x402))); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	if _, err := ReadTCPRequestBody(bytes.NewReader([]byte{0})); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	var b bytes.Buffer
	b.WriteByte(2)
	if _, _, err := ReadTCPResponse(&b); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}

func TestAuthHeaders(t *testing.T) {
	h := make(http.Header)
	if err := WriteClientAuth(h, ClientAuth{Password: "secret", ReceiveBytesPerSecond: 123}); err != nil {
		t.Fatal(err)
	}
	if got := ReadClientAuth(h); got.Password != "secret" || got.ReceiveBytesPerSecond != 123 {
		t.Fatal(got)
	}
	if n := len(h.Get(HeaderPadding)); n < 256 || n >= 2048 {
		t.Fatalf("bad padding %d", n)
	}
	if err := WriteServerAuth(h, ServerAuth{UDPEnabled: true, AutoBandwidth: true}); err != nil {
		t.Fatal(err)
	}
	if got := ReadServerAuth(h); !got.UDPEnabled || !got.AutoBandwidth {
		t.Fatal(got)
	}
}

func TestUDPAndFragments(t *testing.T) {
	m := UDPMessage{SessionID: 0x01020304, PacketID: 17, FragmentCount: 1,
		Address: "example.org:53", Data: bytes.Repeat([]byte{0xaa}, 4000)}
	b, err := AppendUDPMessage(nil, m)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(b[:4]) != m.SessionID {
		t.Fatal("network byte order")
	}
	round, err := ParseUDPMessage(b)
	if err != nil || round.Size() != m.Size() || !bytes.Equal(round.Data, m.Data) {
		t.Fatalf("decode %v, %v", round, err)
	}
	parts, err := FragmentUDPMessage(m, MaxDatagram)
	if err != nil || len(parts) < 2 {
		t.Fatalf("fragment count %d, err %v", len(parts), err)
	}
	var d Defragger
	var output UDPMessage
	var complete bool
	for _, part := range slices.Backward(parts) {
		encoded, err := AppendUDPMessage(nil, part)
		if err != nil || len(encoded) > MaxDatagram {
			t.Fatalf("encode %v, len %d", err, len(encoded))
		}
		fragment, err := ParseUDPMessage(encoded)
		if err != nil {
			t.Fatal(err)
		}
		output, complete, err = d.Feed(fragment, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	if !complete || !bytes.Equal(output.Data, m.Data) || output.FragmentCount != 1 {
		t.Fatal("reassembly mismatch")
	}
}

func TestInterleavedUDPAndIPv6Maximum(t *testing.T) {
	address := "[2001:db8:abcd:0123:4567:89ab:cdef:0123]:443"
	long := UDPMessage{SessionID: 1, PacketID: 0, FragmentCount: 1,
		Address: address, Data: bytes.Repeat([]byte{0x42}, 65507)}
	if long.Size() <= MaxPacket {
		t.Fatal("regression requires wire size larger than a UDP payload")
	}
	parts, err := FragmentUDPMessage(long, MaxDatagram)
	if err != nil {
		t.Fatal(err)
	}
	short := UDPMessage{SessionID: 1, PacketID: 101, FragmentCount: 1,
		Address: "example.org:53", Data: bytes.Repeat([]byte{0x77}, 8192)}
	other, err := FragmentUDPMessage(short, MaxDatagram)
	if err != nil {
		t.Fatal(err)
	}
	var d Defragger
	var receivedLong, receivedShort bool
	now := time.Now()
	for i := 0; i < len(parts) || i < len(other); i++ {
		for _, fragment := range [][]UDPMessage{parts, other} {
			if i >= len(fragment) {
				continue
			}
			serialized, err := AppendUDPMessage(nil, fragment[i])
			if err != nil || len(serialized) > MaxDatagram {
				t.Fatalf("fragment serialization: %v", err)
			}
			decoded, err := ParseUDPMessage(serialized)
			if err != nil {
				t.Fatal(err)
			}
			result, complete, err := d.Feed(decoded, now)
			if err != nil {
				t.Fatal(err)
			}
			if !complete {
				continue
			}
			switch result.PacketID {
			case long.PacketID:
				receivedLong = bytes.Equal(result.Data, long.Data)
			case short.PacketID:
				receivedShort = bytes.Equal(result.Data, short.Data)
			default:
				t.Fatalf("unexpected packet ID %d", result.PacketID)
			}
		}
	}
	if !receivedLong || !receivedShort || len(d.pending) != 0 || d.buffered != 0 {
		t.Fatalf("interleaved UDP corrupted: long=%t short=%t", receivedLong, receivedShort)
	}
}

func TestMalformedUDPPackets(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 8), {0, 0, 0, 1, 0, 0, 0, 1, 1, 0}, {0, 0, 0, 1, 0, 0, 2, 2, 1, 'x', 'y'}} {
		if _, err := ParseUDPMessage(b); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	m := UDPMessage{SessionID: 1, PacketID: 1, FragmentCount: 1, Address: "a:1", Data: []byte("x")}
	if _, err := FragmentUDPMessage(m, 2); err == nil {
		t.Fatal("accepted impossible MTU")
	}
}

func TestFragmentGuards(t *testing.T) {
	m := UDPMessage{SessionID: 1, PacketID: 1, FragmentCount: 2, Address: "a:1", Data: []byte("one")}
	var d Defragger
	if _, ok, err := d.Feed(m, time.Now()); ok || err != nil {
		t.Fatalf("incomplete fragment %v %v", ok, err)
	}
	m.Data = []byte("two")
	if _, _, err := d.Feed(m, time.Now()); !errors.Is(err, ErrMalformed) {
		t.Fatal("conflicting duplicate not rejected", err)
	}
	if len(d.pending) != 0 {
		t.Fatal("did not clear buffered fragments")
	}
	m.Data = []byte("one")
	now := time.Now()
	if _, _, err := d.Feed(m, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Feed(m, now.Add(FragmentTimeout)); err != nil {
		t.Fatal(err)
	}
	if len(d.pending) != 1 || d.pending[1].size != 3 {
		t.Fatal("expired fragment was not reset")
	}
}

func FuzzUDPDecode(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 1, 3, 'a', ':', '1', 'x'})
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseUDPMessage(b)
		if err != nil {
			return
		}
		reencoded, err := AppendUDPMessage(nil, m)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseUDPMessage(reencoded)
		if err != nil || again.Address != m.Address || !bytes.Equal(again.Data, m.Data) {
			t.Fatalf("not stable: %v", err)
		}
	})
}
