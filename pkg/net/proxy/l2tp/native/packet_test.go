package native

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func hexBytes(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWireFixtures(t *testing.T) {
	for _, test := range []struct {
		name, wire      string
		version         int
		tunnel, session uint32
		message         uint16
		payload         string
	}{
		{"v2 HELLO", "c802001400010000000000008008000000000006", 2, 1, 0, 6, ""},
		{"v3 HELLO", "c803001412345678000000008008000000000006", 3, 0x12345678, 0, 6, ""},
		{"v2 compressed PPP", "000200010002214500", 2, 1, 2, 0, "214500"},
		{"v2 data offset", "0202000100020002aaaa214500", 2, 1, 2, 0, "214500"},
		{"v3 data", "0003000012345678010203044500", 3, 0, 0x12345678, 0, "010203044500"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, err := decode(hexBytes(t, test.wire), "")
			if err != nil {
				t.Fatal(err)
			}
			if p.version != test.version || p.tunnel != test.tunnel || p.session != test.session || p.message() != test.message || !bytes.Equal(p.payload, hexBytes(t, test.payload)) {
				t.Fatalf("unexpected packet %+v", p)
			}
		})
	}
	for _, wire := range []string{
		"", "c802001400010000000000008005000000000006", // AVP shorter than its header.
		"c802ffff00010000000000008008000000000006", // Length beyond datagram.
		"c8020014000100000000000080080000ffff0006", // Unknown mandatory AVP.
		"c802001400010000000000008008000000010006", // Message type is not first.
		"020200010002ffff",                         // Offset beyond datagram.
	} {
		if _, err := decode(hexBytes(t, wire), ""); err == nil {
			t.Errorf("accepted malformed packet %s", wire)
		}
	}
}

func TestLegacyAuthenticationVectors(t *testing.T) {
	plain, err := unhide(9, hexBytes(t, "198fb3f1dc1b6f3253326ffe7faeeafd"), "testSecret", hexBytes(t, "01020304"))
	if err != nil || !bytes.Equal(plain, hexBytes(t, "1234")) {
		t.Fatalf("hidden AVP %x, %v", plain, err)
	}
	response, auth, err := mschapResponse("User", "clientPass", hexBytes(t, "5b5d7c7d7b3f2f3e3c2c602132262628"), hexBytes(t, "21402324255e262a28295f2b3a337c7e"))
	if err != nil {
		t.Fatal(err)
	}
	// RFC 2759 section 9.2 independent NT-Response/authenticator vectors.
	if !bytes.Equal(response[24:48], hexBytes(t, "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df")) || auth != "S=407A5589115FD0D6209F510FE9C04566932CDA56" {
		t.Fatalf("MS-CHAPv2 response %x, authenticator %s", response, auth)
	}
}

func TestControlDigestFixture(t *testing.T) {
	wire := hexBytes(t, "c80300390000000000000000800800000000000180170000003b0000000000000000000000000000000000800e000000490102030405060708")
	got, err := controlDigest(wire, "testSecret", nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[27:43], hexBytes(t, "a8747b21c086192da742cb902a8ee924")) {
		t.Fatalf("digest %x", got[27:43])
	}
	if _, err := controlDigest(got, "testSecret", nil, nil, true); err != nil {
		t.Fatal(err)
	}
	got[len(got)-1] ^= 1
	if _, err := controlDigest(got, "testSecret", nil, nil, true); err == nil {
		t.Fatal("accepted tampered control packet")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{0xc8, 2, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 3, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = decode(b, "testSecret") })
}
