package ike

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// RFC 7383 IKE fragmentation. A large protected IKE message — an IKE_AUTH
// bearing a certificate chain, say — can exceed the path MTU and be dropped by
// a fragmentation-hostile middlebox before IP reassembly ever runs. IKE
// fragmentation moves the split up into the IKE layer: the message's encrypted
// content is divided into independently encrypted-and-authenticated Fragment
// (SKF) payloads, one per UDP datagram, and reassembled from their plaintext
// once each is verified.
//
// veepin negotiates support, reassembles inbound fragments, and fragments its
// own output once a protected message would exceed fragmentThreshold.
//
// That last clause was not always true, and the reason it became necessary is
// worth keeping. This comment used to say veepin "never fragments its own
// output: its messages — PSK/EAP auth, no certificates — are always small
// enough to send whole." The premise stopped being true when certificate
// authentication landed: both roles emit a full chain in IKE_AUTH, and an
// RSA-2048 leaf plus an intermediate plus a 256-octet signature puts the
// message at 2.5–3.5 KB. Nothing checked it, because the interop cell that
// would have mints ECDSA P-256 — the smallest certificate that exists.
//
// Sending unfragmented while advertising support is still legal (RFC 7383
// section 2.5.1); sending a 3 KB datagram to a peer that dropped IP fragments
// was never legal, it just looked fine against a fixture that could not
// produce one.
//
// This file holds the capability notify helpers, the per-fragment decrypt, the
// reassembler, and the encoder that mirrors it. The negotiation call sites live
// in sa_init.go (responder) and client.go (initiator), and the reassembly
// dispatch in secured.go / client.go.

// Fragmentation reassembly bounds. A fragmented message is authenticated (it
// rides an established IKE SA, so the sender is not anonymous), but reassembly
// still buffers attacker-influenced state and must be capped.
const (
	maxFragments        = 64
	maxReassembledBytes = 64 * 1024
	fragReassemblyTTL   = 30 * time.Second
)

// skfPrefixLen is the two 16-bit fields (Fragment Number, Total Fragments) that
// precede the IV inside an SKF payload body, after its 4-octet generic payload
// header (RFC 7383 section 2.5).
const skfPrefixLen = 4

// findFragSupported reports whether the peer advertised
// IKE_FRAGMENTATION_SUPPORTED among the given (top-level) payloads.
func findFragSupported(payloads []payload.RawPayload) bool {
	for _, p := range payloads {
		if p.Type != payload.TypeNotify {
			continue
		}
		if n, err := payload.ParseNotify(p.Body); err == nil && n.Type == payload.IKEFragmentationSupported {
			return true
		}
	}
	return false
}

// addFragSupported appends an empty IKE_FRAGMENTATION_SUPPORTED notify to b.
func addFragSupported(b *payload.Builder) {
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.IKEFragmentationSupported,
	}))
}

// decryptSKF verifies and decrypts one SKF (Encrypted Fragment) payload,
// returning its fragment number, the total fragment count, the plaintext chunk,
// and — for the first fragment — the type of the first inner payload (fragments
// after the first carry NextPayload = 0).
//
// Each fragment is an independent unit: its own IV, its own RFC 7296 padding and
// its own ICV, with the associated data spanning the IKE header through the SKF
// payload's Fragment Number / Total Fragments fields (RFC 7383 section 2.5).
// Reassembly concatenates the per-fragment plaintexts in fragment-number order.
func decryptSKF(raw []byte, skf payload.RawPayload,
	suite Suite, keys SAKeys, dir keyDir) (fragNum, total uint16, firstInner payload.PayloadType, plaintext []byte, err error) {

	if len(skf.Body) < skfPrefixLen {
		return 0, 0, 0, nil, fmt.Errorf("ike: SKF payload too short")
	}
	fragNum = binary.BigEndian.Uint16(skf.Body[0:2])
	total = binary.BigEndian.Uint16(skf.Body[2:4])
	ivCtIcv := skf.Body[skfPrefixLen:] // iv || ciphertext || icv

	// AAD is everything before the IV: the IKE header, the SKF generic payload
	// header, and the Fragment Number / Total Fragments fields — i.e. raw up to
	// the start of ivCtIcv.
	bodyStart := len(raw) - len(ivCtIcv)
	if bodyStart < payload.HeaderLen+4+skfPrefixLen {
		return 0, 0, 0, nil, fmt.Errorf("ike: malformed SKF framing")
	}
	aad := raw[:bodyStart]
	// The SKF generic header's NextPayload byte sits 8 octets before the IV: the
	// 4-octet generic header plus the Fragment Number / Total Fragments fields.
	firstInner = payload.PayloadType(raw[bodyStart-4-skfPrefixLen])

	encKey, integKey := encryptKeys(keys, dir)
	padded, err := openSK(suite, encKey, integKey, aad, ivCtIcv)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	plaintext, err = stripRFC7296Pad(padded)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	return fragNum, total, firstInner, plaintext, nil
}

// fragReassembler accumulates the SKF fragments of one IKE message until every
// fragment has arrived, then yields the concatenated inner-payload plaintext.
// One reassembler is embedded per IKE SA (and per client) and reused across
// messages: a fragment for a new message ID resets it. The owner serializes
// access (the responder holds sa.mu; the client is single-threaded per SA).
type fragReassembler struct {
	msgID   uint32
	total   uint16
	parts   [][]byte
	got     int
	bytes   int
	first   payload.PayloadType
	started time.Time
}

// add records one decrypted fragment. Once every fragment of the message has
// arrived it returns the reassembled inner-payload bytes, the first inner
// payload type, and complete=true; otherwise it returns complete=false while
// fragments are still outstanding. A malformed, oversized or over-count fragment
// resets the reassembler and reports an error. Duplicate fragments are ignored.
func (r *fragReassembler) add(msgID uint32, fragNum, total uint16, first payload.PayloadType, chunk []byte) (inner []byte, firstInner payload.PayloadType, complete bool, err error) {
	switch {
	case total == 0 || total > maxFragments:
		return nil, 0, false, fmt.Errorf("ike: bad SKF total-fragments %d", total)
	case fragNum == 0 || fragNum > total:
		return nil, 0, false, fmt.Errorf("ike: bad SKF fragment number %d of %d", fragNum, total)
	}

	// Start fresh for a new message (different ID or a changed total-fragment
	// count), or when a partial reassembly for this same ID has gone stale.
	stale := r.parts != nil && time.Since(r.started) > fragReassemblyTTL
	if r.parts == nil || msgID != r.msgID || total != r.total || stale {
		r.msgID = msgID
		r.total = total
		r.parts = make([][]byte, total)
		r.got = 0
		r.bytes = 0
		r.first = 0
		r.started = time.Now()
	}

	idx := int(fragNum - 1)
	if r.parts[idx] != nil {
		// Duplicate / retransmitted fragment: keep what we have.
		return nil, 0, false, nil
	}
	if r.bytes+len(chunk) > maxReassembledBytes {
		r.reset()
		return nil, 0, false, fmt.Errorf("ike: fragmented message exceeds %d bytes", maxReassembledBytes)
	}
	r.parts[idx] = append([]byte(nil), chunk...)
	r.got++
	r.bytes += len(chunk)
	if fragNum == 1 {
		r.first = first
	}
	if r.got < int(r.total) {
		return nil, 0, false, nil
	}

	// Every fragment is present: concatenate in fragment-number order.
	out := make([]byte, 0, r.bytes)
	for _, p := range r.parts {
		out = append(out, p...)
	}
	firstInner = r.first
	r.reset()
	return out, firstInner, true, nil
}

// reset drops any partial reassembly state.
func (r *fragReassembler) reset() {
	r.parts = nil
	r.got = 0
	r.bytes = 0
	r.total = 0
	r.first = 0
}

// --- outbound fragmentation ---

// fragmentThreshold is the largest IKE message veepin sends whole. Above it, a
// protected message is split into SKF fragments instead.
//
// 1280 is strongSwan's `fragment_size` default and libreswan's, which is the
// argument for it: a value that agrees with the peers this is tested against
// produces the same split they expect, and interop cells then exercise the same
// fragment counts a real deployment would see. It is also the IPv6 minimum MTU
// (RFC 8200 section 5), so a datagram this size crosses any conforming path
// without IP fragmentation -- which is the entire point, since a
// fragmentation-hostile middlebox dropping IP fragments is what RFC 7383 exists
// to route around.
//
// This bounds the IKE message, not the datagram. The outer UDP/IP headers (and
// the 4-octet non-ESP marker on port 4500) ride on top, which is deliberate
// slack rather than an oversight: the alternative is a threshold that changes
// with the underlay's address family mid-session.
const fragmentThreshold = 1280

// skfOverhead is the fixed cost of one fragment beyond its ciphertext: the IKE
// header, the SKF generic payload header, and the Fragment Number / Total
// Fragments fields.
const skfOverhead = payload.HeaderLen + 4 + skfPrefixLen

// buildFragmentedMessage splits innerPayloads across as many SKF-bearing IKE
// messages as it takes to keep each one under fragmentThreshold, and returns
// them in fragment-number order. Every datagram must be sent; the peer
// reassembles them with fragReassembler.
//
// This is the exact mirror of decryptSKF. The wire shape per RFC 7383 section
// 2.5:
//
//	IKE header (NextPayload = SKF, same Message ID on every fragment)
//	  SKF generic header  -- NextPayload = first inner type on fragment 1,
//	                         and 0 (None) on every fragment after it
//	  Fragment Number (2) | Total Fragments (2)
//	  IV | ciphertext | ICV      -- each fragment sealed independently
//
// The NextPayload asymmetry is the part that is easy to get backwards, and
// getting it backwards is invisible against another veepin: both ends would
// agree on the wrong convention. TestFirstFragmentCarriesTheInnerTypeAndTheRest
// pins it from the peer's point of view.
func buildFragmentedMessage(hdr payload.Header, suite Suite, keys SAKeys,
	dir keyDir, firstInner payload.PayloadType, innerPayloads []byte) ([][]byte, error) {

	encKey, integKey := encryptKeys(keys, dir)

	ivLen := suite.Cipher.IVLen()
	icvLen := suite.Cipher.ICVLen()
	if suite.Integ != nil {
		icvLen = suite.Integ.ICVLen
	}
	block := suite.Cipher.BlockLen()

	// Plaintext room per fragment: the threshold less the fixed overhead, the
	// IV, the ICV, and the RFC 7296 pad-length octet that every fragment
	// carries. Block ciphers additionally round up, so leave a whole block of
	// slack rather than solving the rounding exactly -- a fragment one octet
	// over the threshold defeats the purpose, a fragment one block under it
	// costs nothing.
	room := fragmentThreshold - skfOverhead - ivLen - icvLen - 1
	if block > 1 {
		room -= block
	}
	if room <= 0 {
		return nil, fmt.Errorf("ike: cipher overhead leaves no room under the %d-octet fragment threshold", fragmentThreshold)
	}

	total := (len(innerPayloads) + room - 1) / room
	if total == 0 {
		total = 1 // an empty message still fragments into one fragment
	}
	if total > maxFragments {
		return nil, fmt.Errorf("ike: message needs %d fragments, over the %d limit", total, maxFragments)
	}

	out := make([][]byte, 0, total)
	for i := range total {
		chunk := innerPayloads[i*room:]
		if len(chunk) > room {
			chunk = chunk[:room]
		}

		// Only the first fragment names the inner payload type; the rest carry
		// NextPayload = 0, because their plaintext continues a payload chain
		// rather than starting one (RFC 7383 section 2.5.3).
		next := payload.PayloadType(0)
		if i == 0 {
			next = firstInner
		}

		frag, err := sealSKF(hdr, suite, encKey, integKey, ivLen, icvLen, block,
			uint16(i+1), uint16(total), next, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, frag)
	}
	return out, nil
}

// sealSKF builds one SKF-bearing IKE message.
func sealSKF(hdr payload.Header, suite Suite, encKey, integKey []byte,
	ivLen, icvLen, block int, fragNum, total uint16,
	next payload.PayloadType, chunk []byte) ([]byte, error) {

	// Ciphertext length after RFC 7296 padding, computed the same way
	// buildEncryptedMessage does so the two paths cannot drift.
	ctLen := len(chunk) + 1
	if block > 1 {
		if padLen := block - (len(chunk)+1)%block; padLen != block {
			ctLen += padLen
		}
	}
	skfPayloadLen := 4 + skfPrefixLen + ivLen + ctLen + icvLen
	msgLen := payload.HeaderLen + skfPayloadLen

	hdr.NextPayload = payload.TypeSKF
	hdr.Version = 0x20
	hdr.Length = uint32(msgLen)

	// AAD spans everything before the IV: the IKE header, the SKF generic
	// header, and the Fragment Number / Total Fragments fields.
	aad := make([]byte, 0, skfOverhead)
	aad = hdr.Marshal(aad)
	aad = append(aad,
		byte(next), 0x00,
		byte(skfPayloadLen>>8), byte(skfPayloadLen),
	)
	aad = binary.BigEndian.AppendUint16(aad, fragNum)
	aad = binary.BigEndian.AppendUint16(aad, total)

	sealed, err := sealSK(suite, encKey, integKey, aad, chunk)
	if err != nil {
		return nil, err
	}
	if len(sealed) != ivLen+ctLen+icvLen {
		return nil, fmt.Errorf("ike: SKF body length mismatch: got %d want %d",
			len(sealed), ivLen+ctLen+icvLen)
	}

	out := make([]byte, 0, msgLen)
	out = append(out, aad...)
	out = append(out, sealed...)
	return out, nil
}

// sealMaybeFragment is the single choke point for building a protected message.
// It returns one datagram when the message fits, and SKF fragments when it does
// not and the peer advertised support.
//
// When the message is oversize and the peer did NOT advertise support there is
// nothing legal to do but send it whole and let IP fragmentation try. That is
// the pre-RFC-7383 behaviour and it is what every peer without the extension
// expects; returning an error instead would refuse connections that work.
func sealMaybeFragment(hdr payload.Header, suite Suite, keys SAKeys, dir keyDir,
	firstInner payload.PayloadType, inner []byte, peerSupportsFrag bool) ([][]byte, error) {

	if peerSupportsFrag && wouldExceedThreshold(suite, len(inner)) {
		return buildFragmentedMessage(hdr, suite, keys, dir, firstInner, inner)
	}
	pkt, err := buildEncryptedMessage(hdr, suite, keys, dir, firstInner, inner)
	if err != nil {
		return nil, err
	}
	return [][]byte{pkt}, nil
}

// wouldExceedThreshold reports whether an unfragmented message carrying innerLen
// octets of inner payloads would exceed fragmentThreshold. It overestimates the
// padding by a block rather than computing it exactly: the cost of fragmenting
// one message that would have fit by a few octets is one extra datagram, and the
// cost of the opposite mistake is a dropped handshake.
func wouldExceedThreshold(suite Suite, innerLen int) bool {
	icvLen := suite.Cipher.ICVLen()
	if suite.Integ != nil {
		icvLen = suite.Integ.ICVLen
	}
	overhead := payload.HeaderLen + 4 + suite.Cipher.IVLen() + icvLen + 1
	if block := suite.Cipher.BlockLen(); block > 1 {
		overhead += block
	}
	return innerLen+overhead > fragmentThreshold
}
