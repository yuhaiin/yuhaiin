package goldens

// What must hold over a captured WireGuard handshake with wireguard-go.
//
//	wireguard-go  --- handshake initiation (148) --->  veepin server
//	wireguard-go  <--- handshake response   (92) ----  veepin server
//	                        transport data, both ways
//
// Unlike IKE, both handshake messages are fully structured on the wire: fixed
// offsets, no negotiation, and MACs over well-defined prefixes. That makes this
// the strongest check in the package. veepin's responder can be handed the real
// wireguard-go initiation offline and asked to do the whole job — verify mac1
// against its own static key, run the Diffie-Hellman, decrypt the peer's static
// public key — with no container, no network and no timing.
//
// A veepin↔veepin test cannot produce that evidence at any price. Both ends
// would agree on a mac1 computed the same wrong way, which is precisely the
// mutually-consistent-bug class AGENTS.md keeps naming.

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/xen0bit/veepin/internal/capture"
	"github.com/xen0bit/veepin/internal/wireguard/noise"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

const (
	labelWGInitiation = "handshake_initiation"
	labelWGResponse   = "handshake_response"
)

// The cell's fixed test keys, which are also written into
// tests/interop/compose.wireguard-server.yml. They are `wg genkey` output
// generated for this fixture and have never protected anything; the corpus is
// meaningless without them, since checking mac1 means holding the static key it
// is computed over.
//
// TestTheWireGuardKeysStillMatchTheCell reads the compose file and fails if
// these drift from it, so rotating the fixture's keys cannot quietly leave this
// check verifying a handshake nobody makes any more.
const (
	wgServerPrivateB64 = "+IRmjL6NRpthikeXn+jGUJNLe1ZJKQaqeWubiG9+GHs="
	wgClientPublicB64  = "gjMMAROzi5lHFapIKeaAdJ2RhGe0lW24XysGzBd1OSM="
)

// ExtractWireGuard turns a capture of the WireGuard server cell into records.
//
// It keeps one of each handshake message and nothing else. Transport data is
// dropped: it is opaque, it is most of the file, and a persistent keepalive
// means there is an unbounded amount of it.
func ExtractWireGuard(pcapFile []byte) ([]capture.Record, error) {
	datagrams, err := capture.ReadPCAP(pcapFile)
	if err != nil {
		return nil, err
	}

	var out []capture.Record
	for _, d := range capture.FilterPort(datagrams, wgPort) {
		t, ok := wire.Type(d.Payload)
		if !ok {
			continue
		}
		var rec capture.Record
		switch t {
		case wire.TypeHandshakeInitiation:
			rec = capture.Record{Dir: capture.FromPeer, Label: labelWGInitiation}
		case wire.TypeHandshakeResponse:
			rec = capture.Record{Dir: capture.FromVeepin, Label: labelWGResponse}
		default:
			continue
		}
		if _, seen := findLabel(out, rec.Label); seen {
			continue
		}
		rec.Bytes = bytes.Clone(d.Payload)
		out = append(out, rec)
	}
	return out, nil
}

// wgPort is the listen port the cell's entrypoints agree on.
const wgPort = 51820

// CheckWireGuard asserts that veepin's WireGuard codec and its Noise responder
// both agree with wireguard-go, on bytes wireguard-go actually sent.
func CheckWireGuard(c *capture.Corpus) error {
	init, ok := c.Find(labelWGInitiation)
	if !ok {
		return fmt.Errorf("goldens: the capture has no %q", labelWGInitiation)
	}
	if init.Dir != capture.FromPeer {
		return fmt.Errorf("goldens: %s is recorded as %s traffic; the initiation is the oracle "+
			"in this cell and a veepin-authored one would make this check a mirror",
			labelWGInitiation, init.Dir)
	}
	resp, ok := c.Find(labelWGResponse)
	if !ok {
		return fmt.Errorf("goldens: the capture has no %q", labelWGResponse)
	}

	if err := wgInitiationRoundTrips(init.Bytes); err != nil {
		return err
	}
	if err := wgResponseRoundTrips(resp.Bytes); err != nil {
		return err
	}
	return wgResponderConsumesIt(init.Bytes)
}

func wgInitiationRoundTrips(pkt []byte) error {
	if len(pkt) != wire.SizeHandshakeInitiation {
		return fmt.Errorf("goldens: the initiation is %d octets, the format is %d",
			len(pkt), wire.SizeHandshakeInitiation)
	}
	m, err := wire.ParseHandshakeInitiation(pkt)
	if err != nil {
		return fmt.Errorf("goldens: initiation: %w", err)
	}
	got, err := m.Marshal(make([]byte, wire.SizeHandshakeInitiation))
	if err != nil {
		return fmt.Errorf("goldens: initiation: %w", err)
	}
	if !bytes.Equal(got, pkt) {
		return fmt.Errorf("goldens: the initiation does not re-encode\n got %x\nwant %x", got, pkt)
	}
	// The three octets after the type word are reserved and MUST be zero
	// (protocol paper 5.4.2). Nothing else in the message is a fixed value, so
	// this is the one place a hidden field could hide.
	if !bytes.Equal(pkt[1:4], []byte{0, 0, 0}) {
		return fmt.Errorf("goldens: the initiation's reserved octets are %x, not zero", pkt[1:4])
	}
	// mac2 is zero unless the responder has issued a cookie under load, which
	// this cell never does. A nonzero mac2 would mean the capture caught a
	// retry after a cookie reply, and the check below would then be testing a
	// different message than the one it says it is.
	if m.MAC2 != [wire.MACSize]byte{} {
		return fmt.Errorf("goldens: the initiation carries a nonzero mac2, so it followed a " +
			"cookie reply; recapture without the responder under load")
	}
	return nil
}

func wgResponseRoundTrips(pkt []byte) error {
	if len(pkt) != wire.SizeHandshakeResponse {
		return fmt.Errorf("goldens: the response is %d octets, the format is %d",
			len(pkt), wire.SizeHandshakeResponse)
	}
	m, err := wire.ParseHandshakeResponse(pkt)
	if err != nil {
		return fmt.Errorf("goldens: response: %w", err)
	}
	got, err := m.Marshal(make([]byte, wire.SizeHandshakeResponse))
	if err != nil {
		return fmt.Errorf("goldens: response: %w", err)
	}
	if !bytes.Equal(got, pkt) {
		return fmt.Errorf("goldens: the response does not re-encode\n got %x\nwant %x", got, pkt)
	}
	if !bytes.Equal(pkt[1:4], []byte{0, 0, 0}) {
		return fmt.Errorf("goldens: the response's reserved octets are %x, not zero", pkt[1:4])
	}
	return nil
}

// wgResponderConsumesIt is the assertion the rest of the file exists to reach.
//
// It runs veepin's real responder over wireguard-go's real initiation: mac1
// against veepin's static key, then the two Diffie-Hellmans, then the AEAD that
// decrypts the peer's static public key. Every one of those has to match
// wireguard-go's arithmetic exactly, and the recovered key is checkable against
// the one the cell configured — so a wrong answer is not merely an error, it is
// a specific wrong 32 octets.
func wgResponderConsumesIt(pkt []byte) error {
	priv, err := wgKey(wgServerPrivateB64)
	if err != nil {
		return err
	}
	wantPub, err := wgKey(wgClientPublicB64)
	if err != nil {
		return err
	}
	r, err := noise.NewResponder(priv)
	if err != nil {
		return fmt.Errorf("goldens: %w", err)
	}
	peer, timestamp, err := r.Consume(pkt)
	if err != nil {
		return fmt.Errorf("goldens: veepin's responder rejects a real wireguard-go initiation: %w", err)
	}
	if peer != wantPub {
		return fmt.Errorf("goldens: the responder decrypted the peer's static key as %x, "+
			"the cell configured %x", peer, wantPub)
	}
	// TAI64N: the leading octet is 0x40 for any time after 1970, so an all-zero
	// or garbage timestamp says the AEAD "succeeded" over the wrong plaintext.
	if timestamp[0] != 0x40 {
		return fmt.Errorf("goldens: the decrypted timestamp %x is not TAI64N", timestamp)
	}
	return nil
}

func wgKey(b64 string) ([noise.KeySize]byte, error) {
	var k [noise.KeySize]byte
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return k, fmt.Errorf("goldens: key: %w", err)
	}
	if len(raw) != len(k) {
		return k, fmt.Errorf("goldens: key is %d octets, want %d", len(raw), len(k))
	}
	copy(k[:], raw)
	return k, nil
}
