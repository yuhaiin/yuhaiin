// Adapted from xen0bit/veepin (MIT). See ../THIRD_PARTY_LICENSE.
package keys

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"testing"
)

func TestPRFDeterministicAndSized(t *testing.T) {
	secret := []byte("a-secret-value-of-some-length!!!")
	seed := []byte("the seed")
	a := prf(secret, seed, 100)
	b := prf(secret, seed, 100)
	if len(a) != 100 {
		t.Fatalf("prf length = %d, want 100", len(a))
	}
	if !bytes.Equal(a, b) {
		t.Fatal("prf not deterministic")
	}
	// A different seed yields different output.
	if bytes.Equal(a, prf(secret, []byte("other seed"), 100)) {
		t.Fatal("prf ignored the seed")
	}
}

// TestPRFAgainstReference checks the TLS 1.0 PRF against a value computed from an
// independent implementation of the same algorithm, so the primitive — not just
// its self-consistency — is pinned.
func TestPRFAgainstReference(t *testing.T) {
	secret := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	seed := []byte("label" + "seedseed")
	got := prf(secret, seed, 32)
	want := referenceTLS10PRF(secret, seed, 32)
	if !bytes.Equal(got, want) {
		t.Fatalf("prf mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestDeriveDirectionsLineUp is the core key-agreement property: with the same
// key sources and session IDs, the client's encrypt key is the server's decrypt
// key and vice versa, so packets one side seals the other can open.
func TestDeriveDirectionsLineUp(t *testing.T) {
	ks2 := &KeySource2{}
	for i := range ks2.Client.PreMaster {
		ks2.Client.PreMaster[i] = byte(i)
	}
	for i := range ks2.Client.Random1 {
		ks2.Client.Random1[i] = byte(i + 1)
		ks2.Client.Random2[i] = byte(i + 2)
		ks2.Server.Random1[i] = byte(i + 3)
		ks2.Server.Random2[i] = byte(i + 4)
	}
	cSID := SessionID{1, 2, 3, 4, 5, 6, 7, 8}
	sSID := SessionID{8, 7, 6, 5, 4, 3, 2, 1}

	client := ks2.Derive(cSID, sSID, false)
	server := ks2.Derive(cSID, sSID, true)

	if client.EncryptKey != server.DecryptKey || client.EncryptIV != server.DecryptIV {
		t.Error("client encrypt material != server decrypt material")
	}
	if client.DecryptKey != server.EncryptKey || client.DecryptIV != server.EncryptIV {
		t.Error("client decrypt material != server encrypt material")
	}
	if client.EncryptKey == client.DecryptKey {
		t.Error("both directions share a key")
	}
}

func TestMarshalClientLayout(t *testing.T) {
	ks := &KeySource{}
	for i := range ks.PreMaster {
		ks.PreMaster[i] = 0xAA
	}
	msg := ks.MarshalClient("V4,cipher AES-256-GCM", "", "", "IV_PROTO=2")

	if !bytes.Equal(msg[0:4], []byte{0, 0, 0, 0}) {
		t.Error("missing leading zero word")
	}
	if msg[4] != keyMethod2 {
		t.Errorf("key method = %d, want 2", msg[4])
	}
	off := 5 + preMasterLen + 2*randomLen
	// options: uint16 length (incl null) then the string + null.
	optLen := int(binary.BigEndian.Uint16(msg[off:]))
	if optLen != len("V4,cipher AES-256-GCM")+1 {
		t.Errorf("option length = %d", optLen)
	}
	// Empty username/password are length-1 (just the null).
	off += 2 + optLen
	if binary.BigEndian.Uint16(msg[off:]) != 1 {
		t.Error("empty username not encoded as length 1")
	}
}

// TestParseServerRoundTrip builds a server-form message and parses it back.
func TestParseServerRoundTrip(t *testing.T) {
	var r1, r2 [randomLen]byte
	for i := range r1 {
		r1[i] = byte(i + 10)
		r2[i] = byte(i + 20)
	}
	msg := buildServerMessage(r1, r2, "V4,cipher AES-256-GCM,tls-server")

	ks, opts, err := ParseServer(msg)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Random1 != r1 || ks.Random2 != r2 {
		t.Error("server randoms did not round trip")
	}
	if opts != "V4,cipher AES-256-GCM,tls-server" {
		t.Errorf("options = %q", opts)
	}
}

func TestParseServerRejects(t *testing.T) {
	if _, _, err := ParseServer([]byte{0, 0, 0}); err != ErrShortMessage {
		t.Errorf("short message => %v, want ErrShortMessage", err)
	}
	bad := buildServerMessage([randomLen]byte{}, [randomLen]byte{}, "x")
	bad[4] = 3 // wrong key method
	if _, _, err := ParseServer(bad); err != ErrBadKeyMethod {
		t.Errorf("bad method => %v, want ErrBadKeyMethod", err)
	}
}

// buildServerMessage encodes a server key-method-2 message (randoms, no
// pre-master, options string) for ParseServer tests.
func buildServerMessage(r1, r2 [randomLen]byte, options string) []byte {
	var b []byte
	b = append(b, 0, 0, 0, 0)
	b = append(b, keyMethod2)
	b = append(b, r1[:]...)
	b = append(b, r2[:]...)
	b = appendString(b, options)
	return b
}

// referenceTLS10PRF is an independent, plainly-written TLS 1.0 PRF used only to
// cross-check prf. It re-derives the A-chain and output loop from RFC 2246 §5
// rather than calling into the package, so a bug in prf's own loop is caught.
func referenceTLS10PRF(secret, seed []byte, n int) []byte {
	half := (len(secret) + 1) / 2
	md5Out := refPHash(md5.New, secret[:half], seed, n)
	shaOut := refPHash(sha1.New, secret[len(secret)-half:], seed, n)
	out := make([]byte, n)
	for i := range out {
		out[i] = md5Out[i] ^ shaOut[i]
	}
	return out
}

func refPHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	// A[0] = seed; A[i] = HMAC(secret, A[i-1]).
	a := append([]byte(nil), seed...)
	var out []byte
	for len(out) < n {
		am := hmac.New(h, secret)
		am.Write(a)
		a = am.Sum(nil)

		om := hmac.New(h, secret)
		om.Write(a)
		om.Write(seed)
		out = append(out, om.Sum(nil)...)
	}
	return out[:n]
}
