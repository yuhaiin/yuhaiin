package ikev1

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
)

// errNoNATT rejects a peer that never advertised NAT-T. veepin's ESP data path
// is a userspace UDP socket with no raw-IP fallback, so a peer unwilling to
// UDP-encapsulate cannot be talked to at all — better to say so during Main Mode
// than to complete the exchange and silently drop every ESP packet.
var errNoNATT = errors.New("ikev1: peer does not support NAT-T (RFC 3947), which veepin requires for UDP-encapsulated ESP")

// NAT traversal (RFC 3947/3948).
//
// Two things happen here. First, both ends advertise NAT-T support with a Vendor
// ID in MM1/MM2 and then exchange NAT-D payloads in MM3/MM4 — hashes of each
// end's address and port, which differ from what the peer observes exactly when
// an address-rewriting middlebox sits between them. Second, if either end is
// found to be behind a NAT, both float from UDP/500 to UDP/4500, where IKE
// messages carry a four-octet zero prefix (the non-ESP marker) so they can share
// the port with UDP-encapsulated ESP.
//
// veepin always claims to be behind a NAT: it sends a random hash for its own
// address rather than the real one, which is what strongSwan's `encap = yes`
// does. That is not a shortcut around the detection logic but a consequence of
// the architecture — the data path is a userspace UDP socket, so ESP must be
// UDP-encapsulated whether or not a NAT is present, and forcing detection is how
// the protocol expresses that. Real detection still runs, and is logged, so a
// genuine NAT is visible in the logs rather than masked.

// natTVendorIDs are the well-known Vendor ID payloads (MD5 hashes of the spec
// names) advertising NAT-T support. We send the RFC 3947 ID and recognize the
// widely deployed drafts, since peers key their payload numbering off whichever
// they see.
var natTVendorIDs = struct {
	rfc3947  []byte
	draft02n []byte
	draft02  []byte
	draft03  []byte
}{
	rfc3947:  mustHex("4a131c81070358455c5728f20e95452f"), // "RFC 3947"
	draft02n: mustHex("90cb80913ebb696e086381b5ec427b1f"), // "draft-ietf-ipsec-nat-t-ike-02\n"
	draft02:  mustHex("cd60464335df21f87cfdb2fc68b6a448"), // "draft-ietf-ipsec-nat-t-ike-02"
	draft03:  mustHex("7d9419a65310ca6f2c179d9215529d56"), // "draft-ietf-ipsec-nat-t-ike-03"
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("ikev1: bad vendor ID constant: " + err.Error())
	}
	return b
}

// natTVendorPayloads are the Vendor ID payloads we offer in MM1 (and echo in
// MM2). Offering the drafts as well as the RFC keeps older peers — including the
// stock native-OS clients L2TP/IPsec exists for — willing to do NAT-T at all.
func natTVendorPayloads() []payload {
	return []payload{
		{typ: payloadVendorID, body: natTVendorIDs.rfc3947},
		{typ: payloadVendorID, body: natTVendorIDs.draft03},
		{typ: payloadVendorID, body: natTVendorIDs.draft02n},
		{typ: payloadVendorID, body: natTVendorIDs.draft02},
	}
}

// peerSupportsNATT reports whether any of the peer's Vendor IDs is a NAT-T one.
func peerSupportsNATT(payloads []payload) bool {
	for _, p := range payloads {
		if p.typ != payloadVendorID {
			continue
		}
		for _, vid := range [][]byte{
			natTVendorIDs.rfc3947, natTVendorIDs.draft03,
			natTVendorIDs.draft02n, natTVendorIDs.draft02,
		} {
			if constEq(p.body, vid) {
				return true
			}
		}
	}
	return false
}

// natdHash is HASH(CKY-I | CKY-R | IP | Port) under the negotiated phase-1 hash
// (RFC 3947 section 3.2) — the value a peer recomputes from the addresses it
// actually observes. It uses the bare hash rather than the keyed PRF, so it is
// available from MM3, before the DH exchange has produced any keys.
func (s *Session) natdHash(ip net.IP, port uint16) []byte {
	ctor, err := hashCtor(s.prop.hash)
	if err != nil {
		return nil
	}
	h := ctor()
	h.Write(s.initCookie[:])
	h.Write(s.respCookie[:])
	if v4 := ip.To4(); v4 != nil {
		h.Write(v4)
	} else if v6 := ip.To16(); v6 != nil {
		h.Write(v6)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	h.Write(p[:])
	return h.Sum(nil)
}

// natdPayloads builds the NAT-D pair for MM3/MM4. RFC 3947 orders them
// destination-first: the peer's address, then ours. Ours is deliberately random
// so the peer detects a NAT and floats — see the note at the top of this file.
func (s *Session) natdPayloads() []payload {
	local := make([]byte, len(s.natdHash(s.cfg.LocalIP, s.cfg.LocalPort)))
	_, _ = rand.Read(local)
	return []payload{
		{typ: payloadNATD, body: s.natdHash(s.cfg.PeerIP, s.cfg.PeerPort)},
		{typ: payloadNATD, body: local},
	}
}

// detectNAT interprets the peer's NAT-D payloads: the first is the hash of our
// address as the peer sees it (a mismatch means we are behind a NAT), the rest
// are the peer's own (no match means the peer is behind one). It reports what it
// found for logging; the float itself is unconditional.
func (s *Session) detectNAT(payloads []payload) (localBehind, peerBehind bool) {
	var got [][]byte
	for _, p := range payloads {
		if p.typ == payloadNATD || p.typ == payloadNATDDraft {
			got = append(got, p.body)
		}
	}
	if len(got) == 0 {
		return false, false
	}
	localBehind = !constEq(got[0], s.natdHash(s.cfg.LocalIP, s.cfg.LocalPort))

	peerBehind = true
	want := s.natdHash(s.cfg.PeerIP, s.cfg.PeerPort)
	for _, h := range got[1:] {
		if constEq(h, want) {
			peerBehind = false
			break
		}
	}
	return localBehind, peerBehind
}

// float switches this session onto the NAT-T port for every subsequent message.
// Both ends do it after the NAT-D exchange, so MM5 onward — and all ESP — ride
// UDP/4500 behind the non-ESP marker.
func (s *Session) float(payloads []payload) {
	localBehind, peerBehind := s.detectNAT(payloads)
	s.floated = true
	s.logger.Printf("ikev1: NAT-T: floating to UDP/%d (nat detected: local=%v peer=%v)",
		nattPort, localBehind, peerBehind)
}
