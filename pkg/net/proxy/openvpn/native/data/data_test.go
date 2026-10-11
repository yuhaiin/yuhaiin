// Adapted from xen0bit/veepin (MIT). See ../THIRD_PARTY_LICENSE.
package data

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native/keys"
)

// cipherPair builds a client and server Cipher with crossed keys, so packets one
// seals the other opens, mirroring how key derivation hands each side opposite
// slots.
func cipherPair(t *testing.T) (client, server *Cipher) {
	t.Helper()
	var kA, kB [keys.GCMKeyLen]byte
	var ivA, ivB [keys.ImplicitIVLen]byte
	for i := range kA {
		kA[i] = byte(i + 1)
		kB[i] = byte(i + 100)
	}
	for i := range ivA {
		ivA[i] = byte(i + 8)
		ivB[i] = byte(i + 200)
	}
	clientKeys := keys.DataKeys{EncryptKey: kA, DecryptKey: kB, EncryptIV: ivA, DecryptIV: ivB}
	serverKeys := keys.DataKeys{EncryptKey: kB, DecryptKey: kA, EncryptIV: ivB, DecryptIV: ivA}

	var err error
	client, err = New(clientKeys, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err = New(serverKeys, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestSealOpenRoundTrip(t *testing.T) {
	client, server := cipherPair(t)
	msg := []byte("an inner IP packet's worth of bytes goes here")
	sealed, err := client.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	// The wire packet should be exactly Overhead longer than the plaintext.
	if len(sealed) != len(msg)+Overhead {
		t.Errorf("sealed len = %d, want %d", len(sealed), len(msg)+Overhead)
	}
	// Opcode byte names P_DATA_V2.
	if sealed[0]>>opcodeShift != PDataV2 {
		t.Errorf("opcode = %d, want P_DATA_V2", sealed[0]>>opcodeShift)
	}
	got, err := server.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("round trip = %q, want %q", got, msg)
	}
}

func TestPacketIDsIncrement(t *testing.T) {
	client, server := cipherPair(t)
	for i := range 5 {
		sealed, err := client.Seal([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		id := uint32(sealed[4])<<24 | uint32(sealed[5])<<16 | uint32(sealed[6])<<8 | uint32(sealed[7])
		if id != uint32(i+1) {
			t.Errorf("packet %d has ID %d, want %d", i, id, i+1)
		}
		if _, err := server.Open(sealed); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
}

func TestPingRoundTrips(t *testing.T) {
	client, server := cipherPair(t)
	sealed, err := client.Seal(Ping)
	if err != nil {
		t.Fatal(err)
	}
	got, err := server.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPing(got) {
		t.Error("keepalive ping not recognised after round trip")
	}
	if IsPing([]byte("not a ping")) {
		t.Error("IsPing matched a non-ping payload")
	}
}

// openCopy opens a copy of pkt, since Open decrypts in place and the pump always
// hands it a fresh buffer.
func openCopy(c *Cipher, pkt []byte) ([]byte, error) {
	return c.Open(append([]byte(nil), pkt...))
}

func TestOpenRejectsReplay(t *testing.T) {
	client, server := cipherPair(t)
	sealed, err := client.Seal([]byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openCopy(server, sealed); err != nil {
		t.Fatal(err)
	}
	// The exact same packet again must be rejected as a replay.
	if _, err := openCopy(server, sealed); err != errReplay {
		t.Errorf("replay accepted: %v, want errReplay", err)
	}
}

func TestOpenAcceptsReorderWithinWindow(t *testing.T) {
	client, server := cipherPair(t)
	var packets [][]byte
	for i := range 4 {
		p, err := client.Seal([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p)
	}
	// Deliver out of order: 3, 1, 0, 2. All are within the window and fresh.
	for _, i := range []int{3, 1, 0, 2} {
		if _, err := openCopy(server, packets[i]); err != nil {
			t.Errorf("reordered open of packet %d failed: %v", i, err)
		}
	}
	// Re-delivering any is now a replay.
	if _, err := openCopy(server, packets[1]); err != errReplay {
		t.Errorf("reordered replay accepted: %v", err)
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	client, server := cipherPair(t)
	sealed, err := client.Seal([]byte("authentic"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the peer-id header (authenticated but not encrypted): the
	// AEAD tag must reject it.
	tampered := append([]byte(nil), sealed...)
	tampered[1] ^= 0x01
	if _, err := server.Open(tampered); err == nil {
		t.Error("tampered header accepted")
	}
	// Flip a ciphertext bit too.
	tampered = append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := server.Open(tampered); err == nil {
		t.Error("tampered ciphertext accepted")
	}
}

// TestDataPathAllocations pins the per-packet allocation cost of the hot path:
// one allocation to seal (the output buffer) and none to open (decrypt in
// place). A regression here means the AEAD nonce or a reassembly buffer has
// started escaping again.
func TestDataPathAllocations(t *testing.T) {
	client, server := cipherPair(t)
	inner := ipv4(1400)

	if n := testing.AllocsPerRun(100, func() {
		if _, err := client.Seal(inner); err != nil {
			t.Fatal(err)
		}
	}); n > 1 {
		t.Errorf("Seal allocates %.0f times per packet, want 1", n)
	}

	// Pre-seal a batch with distinct counters so Open sees fresh packets, and give
	// each run its own buffer since Open decrypts in place.
	const batch = 2048
	pkts := make([][]byte, batch)
	for i := range pkts {
		p, err := client.Seal(inner)
		if err != nil {
			t.Fatal(err)
		}
		pkts[i] = p
	}
	scratch := make([]byte, 1400+Overhead)
	i := 0
	if n := testing.AllocsPerRun(batch-1, func() {
		buf := scratch[:len(pkts[i])]
		copy(buf, pkts[i])
		i++
		if _, err := server.Open(buf); err != nil {
			t.Fatal(err)
		}
	}); n > 0 {
		t.Errorf("Open allocates %.0f times per packet, want 0", n)
	}
}

func TestReplayWindowTooOld(t *testing.T) {
	var w replayWindow
	if !w.accept(100) {
		t.Fatal("first packet rejected")
	}
	// A packet far below the window is rejected.
	if w.accept(1) {
		t.Error("packet older than the window accepted")
	}
	// One just inside is accepted.
	if !w.accept(100 - 63) {
		t.Error("packet at the window edge rejected")
	}
	if w.accept(0) {
		t.Error("packet ID 0 accepted")
	}
}

// TestSealPaddedRoundTrip covers the shaper's OpenVPN vehicle. The data channel
// length-delimits its payload, so filler past the inner packet is delimited only
// by that packet's own IP header — the receiver has to trim by it, which is what
// makes the padding inert.
func TestSealPaddedRoundTrip(t *testing.T) {
	client, server := cipherPair(t)
	for _, size := range []int{20, 64, 576} {
		msg := ipv4(size)
		sealed, err := client.SealPadded(msg, 1400)
		if err != nil {
			t.Fatal(err)
		}
		if want := 1400 + Overhead; len(sealed) != want {
			t.Errorf("size %d: sealed len = %d, want %d", size, len(sealed), want)
		}
		// A padded small packet must be indistinguishable on the wire from a
		// genuine full one — that is the whole point.
		if full, ferr := client.Seal(ipv4(1400)); ferr != nil {
			t.Fatal(ferr)
		} else if len(sealed) != len(full) {
			t.Errorf("size %d: padded %d != genuine full %d", size, len(sealed), len(full))
		}
		got, err := server.Open(sealed)
		if err != nil {
			t.Fatalf("size %d: open: %v", size, err)
		}
		if !bytes.Equal(got[:size], msg) {
			t.Errorf("size %d: inner packet corrupted", size)
		}
		for i, b := range got[size:] {
			if b != 0 {
				t.Fatalf("size %d: filler byte %d = %#x, want 0 — pooled scratch leaked", size, i+size, b)
			}
		}
	}
}

// A target at or below the packet's own size must leave it alone.
func TestSealPaddedIsAFloor(t *testing.T) {
	client, _ := cipherPair(t)
	msg := ipv4(1400)
	padded, err := client.SealPadded(msg, 576)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(msg) + Overhead; len(padded) != want {
		t.Errorf("padded len = %d, want %d (a target below the packet must not change it)", len(padded), want)
	}
}

// TestPaddedDataPathAllocations holds the padded path to the same single
// allocation as the plain one: the pooled plaintext scratch exists precisely so
// shaping does not add one.
func TestPaddedDataPathAllocations(t *testing.T) {
	client, _ := cipherPair(t)
	inner := ipv4(64)
	if n := testing.AllocsPerRun(100, func() {
		if _, err := client.SealPadded(inner, 1400); err != nil {
			t.Fatal(err)
		}
	}); n > 1 {
		t.Errorf("SealPadded allocates %.0f times per packet, want 1", n)
	}
}

func ipv4(size int) []byte {
	size = max(size, 20)
	p := make([]byte, size)
	p[0] = 0x45
	p[2] = byte(size >> 8)
	p[3] = byte(size)
	return p
}
