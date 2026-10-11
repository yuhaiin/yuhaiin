// Adapted from xen0bit/veepin (MIT). See ../THIRD_PARTY_LICENSE.
package tlswrap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

// testKey builds a static key from deterministic bytes, formatted like an
// OpenVPN static key file so ParseStaticKey is exercised too.
func testKey(t *testing.T) *StaticKey {
	t.Helper()
	var raw [StaticKeyLen]byte
	for i := range raw {
		raw[i] = byte(i * 7)
	}
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	h := hex.EncodeToString(raw[:])
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i : i+32])
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	k, err := ParseStaticKey([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if k.raw != raw {
		t.Fatal("parsed key does not match input")
	}
	return k
}

// pkt builds a fake marshalled control packet: opcode | session_id | body.
func pkt(body string) []byte {
	p := make([]byte, headerLen)
	p[0] = 7 << 3 // P_CONTROL_HARD_RESET_CLIENT_V2, key_id 0
	for i := 1; i < headerLen; i++ {
		p[i] = byte(0xa0 + i)
	}
	return append(p, body...)
}

func roundTrip(t *testing.T, client, server Wrapper) {
	t.Helper()
	msg := pkt("a control-channel payload")
	wire, err := client.Wrap(msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wire[:1], msg[:1]) && len(wire) == len(msg) {
		t.Fatal("wrap did not change the packet")
	}
	// The opcode and session ID must survive in the clear for demux and the codec.
	if !bytes.Equal(wire[:headerLen], msg[:headerLen]) {
		t.Errorf("header not preserved in the clear")
	}
	got, err := server.Unwrap(wire)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("round trip = %x, want %x", got, msg)
	}
}

func TestAuthRoundTrip(t *testing.T) {
	k := testKey(t)
	d, _ := ParseDigest("SHA256")
	// Client sends Inverse, server receives Normal — their slots line up.
	client := NewAuth(k, Inverse, d)
	server := NewAuth(k, Normal, d)
	roundTrip(t, client, server)
}

func TestAuthBidirectional(t *testing.T) {
	k := testKey(t)
	d, _ := ParseDigest("SHA1")
	client := NewAuth(k, Bidirectional, d)
	server := NewAuth(k, Bidirectional, d)
	roundTrip(t, client, server)
}

func TestCryptRoundTrip(t *testing.T) {
	k := testKey(t)
	client, err := NewCrypt(k, Inverse)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewCrypt(k, Normal)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, client, server)
	// tls-crypt must actually hide the body: the plaintext must not appear on the
	// wire.
	msg := pkt("SECRETSECRETSECRET")
	wire, _ := client.Wrap(msg)
	if bytes.Contains(wire, []byte("SECRETSECRETSECRET")) {
		t.Error("tls-crypt left the body in the clear")
	}
}

func TestAuthRejectsForgery(t *testing.T) {
	k := testKey(t)
	d, _ := ParseDigest("SHA256")
	client := NewAuth(k, Inverse, d)
	server := NewAuth(k, Normal, d)
	wire, _ := client.Wrap(pkt("payload"))
	wire[len(wire)-1] ^= 0x01 // flip a body bit
	if _, err := server.Unwrap(wire); err != ErrAuth {
		t.Errorf("forged packet: %v, want ErrAuth", err)
	}
}

func TestCryptRejectsForgery(t *testing.T) {
	k := testKey(t)
	client, _ := NewCrypt(k, Inverse)
	server, _ := NewCrypt(k, Normal)
	wire, _ := client.Wrap(pkt("payload"))
	wire[cryptTagOff] ^= 0x01 // flip a tag bit
	if _, err := server.Unwrap(wire); err != ErrAuth {
		t.Errorf("forged packet: %v, want ErrAuth", err)
	}
}

func TestWrongKeyFails(t *testing.T) {
	d, _ := ParseDigest("SHA256")
	client := NewAuth(testKey(t), Inverse, d)
	var other [StaticKeyLen]byte
	rand.Read(other[:])
	server := NewAuth(&StaticKey{raw: other}, Normal, d)
	wire, _ := client.Wrap(pkt("payload"))
	if _, err := server.Unwrap(wire); err != ErrAuth {
		t.Errorf("mismatched key: %v, want ErrAuth", err)
	}
}

func TestReplayRejected(t *testing.T) {
	k := testKey(t)
	d, _ := ParseDigest("SHA256")
	client := NewAuth(k, Inverse, d)
	server := NewAuth(k, Normal, d)
	wire, _ := client.Wrap(pkt("payload"))
	if _, err := server.Unwrap(append([]byte(nil), wire...)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Unwrap(append([]byte(nil), wire...)); err != ErrReplay {
		t.Errorf("replay: %v, want ErrReplay", err)
	}
}

func TestParseStaticKeyRejects(t *testing.T) {
	if _, err := ParseStaticKey([]byte("not a key")); err == nil {
		t.Error("accepted non-key input")
	}
	short := "-----BEGIN OpenVPN Static key V1-----\ndeadbeef\n-----END OpenVPN Static key V1-----\n"
	if _, err := ParseStaticKey([]byte(short)); err == nil {
		t.Error("accepted short key")
	}
}
