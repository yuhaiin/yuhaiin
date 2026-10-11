package goldens

// What must hold over a captured IKEv2 exchange with strongSwan.
//
// The exchange the corpus holds, and which of it is readable:
//
//	veepin  --- IKE_SA_INIT request  --->  strongSwan     in the clear
//	veepin  <--- IKE_SA_INIT response ---  strongSwan     in the clear
//	veepin  --- IKE_AUTH request     --->  strongSwan     one SK payload
//	veepin  <--- IKE_AUTH response   ---   strongSwan     one SK payload
//
// Only the first two carry payloads a parser can reach without keys, and they
// are the two worth the most: every algorithm the peer will accept, its DH
// public value, and the notify chain that decides how the rest of the exchange
// behaves. The IKE_AUTH pair is kept anyway — as a framing check, and because
// real encrypted messages are the seed corpus a fuzz target actually wants.

import (
	"bytes"
	"fmt"

	"github.com/xen0bit/veepin/internal/capture"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// The two UDP ports IKE lives on, and the four-octet zero prefix that
// distinguishes an IKE message from ESP once both share 4500 (RFC 3948 2.2).
const (
	portIKE    = 500
	portIKENAT = 4500
)

var nonESPMarker = []byte{0, 0, 0, 0}

// ExtractIKEv2 turns a capture of the IKEv2 cell into labelled records.
//
// It keeps only IKE messages: everything on 500, and everything on 4500 that
// carries the non-ESP marker. The ESP data path that follows shares 4500 and
// would otherwise be most of the file, none of it parseable, and different on
// every run.
//
// Direction comes from the header's own Initiator flag rather than from the
// addresses. veepin is the initiator in this cell, and reading it from the
// message means the labels stay right if the capture is ever taken from the
// other container.
func ExtractIKEv2(pcapFile []byte) ([]capture.Record, error) {
	datagrams, err := capture.ReadPCAP(pcapFile)
	if err != nil {
		return nil, err
	}

	var out []capture.Record
	for _, d := range capture.FilterPort(datagrams, portIKE, portIKENAT) {
		msg := d.Payload
		if d.Src.Port() == portIKENAT || d.Dst.Port() == portIKENAT {
			if !bytes.HasPrefix(msg, nonESPMarker) {
				continue // ESP, not IKE.
			}
			msg = msg[len(nonESPMarker):]
		}
		hdr, err := payload.ParseHeader(msg)
		if err != nil {
			// Something on an IKE port that is not an IKE message is worth an
			// error rather than a skip: it means the filter is wrong, and a
			// silently short corpus is the thing this package exists to avoid.
			return nil, fmt.Errorf("goldens: a datagram on an IKE port is not an IKE message: %w", err)
		}
		if int(hdr.Length) != len(msg) {
			return nil, fmt.Errorf("goldens: IKE header claims %d octets, the datagram carried %d",
				hdr.Length, len(msg))
		}

		label := ikeLabel(hdr)
		if label == "" {
			continue
		}
		// Only the first of each: a retransmit is the same message again, and a
		// corpus that held three copies of one exchange would just be slower to
		// read.
		if _, seen := findLabel(out, label); seen {
			continue
		}
		out = append(out, capture.Record{
			Dir:   ikeDir(hdr),
			Label: label,
			Bytes: bytes.Clone(msg),
		})
	}
	return out, nil
}

// ikeLabel names a message by its exchange and role. An exchange this corpus is
// not recording returns "".
func ikeLabel(h payload.Header) string {
	suffix := "request"
	if h.IsResponse() {
		suffix = "response"
	}
	switch h.ExchangeType {
	case payload.IKE_SA_INIT:
		return "ike_sa_init_" + suffix
	case payload.IKE_AUTH:
		return "ike_auth_" + suffix
	default:
		return ""
	}
}

// ikeDir reads who sent a message off the header. In this cell veepin is the
// original initiator, so the I flag and the R flag together name the sender:
// an initiator-flagged request is veepin's, an initiator-flagged response is
// the peer answering as the responder.
func ikeDir(h payload.Header) capture.Direction {
	if h.IsInitiator() && !h.IsResponse() {
		return capture.FromVeepin
	}
	return capture.FromPeer
}

func findLabel(rs []capture.Record, label string) (capture.Record, bool) {
	for _, r := range rs {
		if r.Label == label {
			return r, true
		}
	}
	return capture.Record{}, false
}

// Labels the recorder assigns, and the check requires.
const (
	labelSAInitRequest  = "ike_sa_init_request"
	labelSAInitResponse = "ike_sa_init_response"
	labelAuthRequest    = "ike_auth_request"
	labelAuthResponse   = "ike_auth_response"
)

// CheckIKEv2 asserts that veepin's IKEv2 codec agrees with strongSwan's, to the
// octet, on bytes strongSwan actually sent.
//
// The re-encode is the point. A parser that accepts the peer's message proves
// only that veepin is tolerant; re-emitting the identical octets proves the two
// encoders agree, which is the one thing a veepin↔veepin test can never show.
// It catches the class AGENTS.md keeps returning to — a reserved field written
// as 1 at both ends, a length computed the same wrong way twice — because the
// oracle here was written by somebody else.
func CheckIKEv2(c *capture.Corpus) error {
	for _, want := range []string{labelSAInitRequest, labelSAInitResponse, labelAuthRequest, labelAuthResponse} {
		if _, ok := c.Find(want); !ok {
			return fmt.Errorf("goldens: the capture has no %q; it is not a complete IKEv2 exchange", want)
		}
	}

	for _, r := range c.Records {
		if err := ikeMessageRoundTrips(r); err != nil {
			return err
		}
	}

	resp, _ := c.Find(labelSAInitResponse)
	if resp.Dir != capture.FromPeer {
		return fmt.Errorf("goldens: %s is recorded as %s traffic; the responder's message is the oracle here "+
			"and a veepin-authored one would make this check a mirror", labelSAInitResponse, resp.Dir)
	}
	return checkResponderSAInit(resp.Bytes)
}

// ikeMessageRoundTrips parses one IKE message and re-encodes every layer of it,
// requiring the same octets back at each layer.
func ikeMessageRoundTrips(r capture.Record) error {
	hdr, err := payload.ParseHeader(r.Bytes)
	if err != nil {
		return fmt.Errorf("goldens: %s: header: %w", r.Label, err)
	}
	if got := hdr.Marshal(nil); !bytes.Equal(got, r.Bytes[:payload.HeaderLen]) {
		return fmt.Errorf("goldens: %s: the header does not re-encode\n got %x\nwant %x",
			r.Label, got, r.Bytes[:payload.HeaderLen])
	}
	if int(hdr.Length) != len(r.Bytes) {
		return fmt.Errorf("goldens: %s: header length %d but %d octets were captured",
			r.Label, hdr.Length, len(r.Bytes))
	}

	msg, err := payload.ParseMessage(r.Bytes)
	if err != nil {
		return fmt.Errorf("goldens: %s: %w", r.Label, err)
	}

	if encrypted(msg) {
		return skFramingIsWellFormed(r.Label, msg, r.Bytes)
	}

	// The payload chain, rebuilt by veepin's own Builder. This is where a
	// disagreement about the generic payload header — the critical bit, the
	// reserved bits, how a length is counted — surfaces.
	b := payload.NewBuilder()
	for _, p := range msg.Payloads {
		b.Add(p.Type, p.Critical, p.Body)
	}
	if got, want := b.Bytes(), r.Bytes[payload.HeaderLen:]; !bytes.Equal(got, want) {
		return fmt.Errorf("goldens: %s: the payload chain does not re-encode\n got %x\nwant %x", r.Label, got, want)
	}
	if b.FirstType() != msg.FirstPayloadType() {
		return fmt.Errorf("goldens: %s: rebuilt chain starts with %v, captured one with %v",
			r.Label, b.FirstType(), msg.FirstPayloadType())
	}

	for _, p := range msg.Payloads {
		if err := bodyRoundTrips(r.Label, p); err != nil {
			return err
		}
	}
	return nil
}

// encrypted reports whether a message's payloads are an SK or SKF, which is the
// case the chain rebuild above cannot handle.
func encrypted(m *payload.Message) bool {
	for _, p := range m.Payloads {
		if p.Type == payload.TypeSK || p.Type == payload.TypeSKF {
			return true
		}
	}
	return false
}

// skFramingIsWellFormed checks an encrypted message's outer framing.
//
// The chain rebuild is deliberately not used here, and the reason is the first
// thing this corpus taught. Builder.Add links each payload to the next one and
// writes 0 into the last — which is right for every payload except SK, whose
// NextPayload field does not name the next payload at all. RFC 7296 3.14 gives
// it a different job: it names the first payload *inside* the ciphertext. A
// captured IKE_AUTH request therefore ends `23 00 01 4f` (next = IDi) where a
// rebuild produces `00 00 01 4f`, and the two disagree without either being
// wrong.
//
// veepin's own encoder gets this right — internal/ikev2/ike threads the inner
// first-payload type through sealMaybeFragment precisely for it — so what the
// mismatch caught was an over-general assertion, not a bug. It is recorded
// rather than quietly worked around because "the last payload's NextPayload is
// zero" is exactly the kind of near-universal truth a tidy-up would restore.
func skFramingIsWellFormed(label string, m *payload.Message, raw []byte) error {
	if len(m.Payloads) != 1 {
		return fmt.Errorf("goldens: %s: an encrypted message carries %d payloads; "+
			"RFC 7296 3.14 allows exactly one SK, and it must be last", label, len(m.Payloads))
	}
	sk := m.Payloads[0]
	if sk.Critical {
		return fmt.Errorf("goldens: %s: the SK payload is marked critical", label)
	}
	// Zero here would say the ciphertext decrypts to nothing at all.
	if next := payload.PayloadType(raw[payload.HeaderLen]); next == payload.NoNextPayload {
		return fmt.Errorf("goldens: %s: the SK payload names no inner first payload", label)
	}
	if want := len(raw) - payload.HeaderLen - genericPayloadHeaderLen; len(sk.Body) != want {
		return fmt.Errorf("goldens: %s: the SK body is %d octets, the framing leaves room for %d",
			label, len(sk.Body), want)
	}
	return nil
}

// genericPayloadHeaderLen is RFC 7296 3.2's four-octet payload header. The
// payload package keeps its own unexported copy; this is the same number, named
// here so the arithmetic above reads.
const genericPayloadHeaderLen = 4

// bodyRoundTrips re-encodes one payload body through its own Parse/Marshal
// pair. A payload with no decoder here is skipped rather than failed: SK is
// ciphertext by construction, and a new payload type appearing is a thing to
// find out about from the live cell, not a reason for the offline check to
// refuse a corpus it can still mostly verify.
func bodyRoundTrips(label string, p payload.RawPayload) error {
	var got []byte
	switch p.Type {
	case payload.TypeSA:
		sa, err := payload.ParseSA(p.Body)
		if err != nil {
			return fmt.Errorf("goldens: %s: SA: %w", label, err)
		}
		got = payload.MarshalSA(sa)
	case payload.TypeKE:
		ke, err := payload.ParseKE(p.Body)
		if err != nil {
			return fmt.Errorf("goldens: %s: KE: %w", label, err)
		}
		got = payload.MarshalKE(ke)
	case payload.TypeNonce:
		got = payload.MarshalNonce(payload.ParseNonce(p.Body))
	case payload.TypeNotify:
		n, err := payload.ParseNotify(p.Body)
		if err != nil {
			return fmt.Errorf("goldens: %s: Notify: %w", label, err)
		}
		got = payload.MarshalNotify(n)
	default:
		return nil
	}
	if !bytes.Equal(got, p.Body) {
		return fmt.Errorf("goldens: %s: a %v payload does not re-encode\n got %x\nwant %x",
			label, p.Type, got, p.Body)
	}
	return nil
}

// checkResponderSAInit asserts the things about strongSwan's answer that veepin
// depends on and that no unit test can establish.
func checkResponderSAInit(msg []byte) error {
	hdr, err := payload.ParseHeader(msg)
	if err != nil {
		return err
	}
	if hdr.ExchangeType != payload.IKE_SA_INIT || !hdr.IsResponse() || hdr.MessageID != 0 {
		return fmt.Errorf("goldens: the responder's first message is exchange %v, response=%v, msgid=%d",
			hdr.ExchangeType, hdr.IsResponse(), hdr.MessageID)
	}

	m, err := payload.ParseMessage(msg)
	if err != nil {
		return err
	}

	// A responder's SA payload carries exactly one proposal — its choice. More
	// than one would mean veepin was reading a negotiation as a settlement.
	saRaw := m.Find(payload.TypeSA)
	if saRaw == nil {
		return fmt.Errorf("goldens: the responder sent no SA payload")
	}
	sa, err := payload.ParseSA(saRaw.Body)
	if err != nil {
		return err
	}
	if len(sa.Proposals) != 1 {
		return fmt.Errorf("goldens: the responder chose %d proposals; a chosen SA is one",
			len(sa.Proposals))
	}
	for _, t := range []payload.TransformType{payload.TransformENCR, payload.TransformPRF, payload.TransformDH} {
		if _, ok := sa.Proposals[0].Get(t); !ok {
			return fmt.Errorf("goldens: the chosen proposal names no transform of type %v", t)
		}
	}

	// The KE group must be the one the chosen proposal names, or the shared
	// secret is computed over a group nobody agreed to.
	keRaw := m.Find(payload.TypeKE)
	if keRaw == nil {
		return fmt.Errorf("goldens: the responder sent no KE payload")
	}
	ke, err := payload.ParseKE(keRaw.Body)
	if err != nil {
		return err
	}
	dh, _ := sa.Proposals[0].Get(payload.TransformDH)
	if uint16(dh.ID) != ke.Group {
		return fmt.Errorf("goldens: the responder chose DH group %d but its KE payload carries group %d",
			dh.ID, ke.Group)
	}

	if n := payload.ParseNonce(func() []byte {
		if p := m.Find(payload.TypeNonce); p != nil {
			return p.Body
		}
		return nil
	}()); len(n) < 16 {
		return fmt.Errorf("goldens: the responder's nonce is %d octets; RFC 7296 3.9 requires at least 16", len(n))
	}

	// This is the assertion with teeth. veepin only fragments its own IKE
	// output when the peer advertises support, and before the claims-and-reach
	// work it never fragmented at all — so a peer that stopped advertising
	// FRAGMENTATION_SUPPORTED would put the certificate path straight back into
	// the bug that was just fixed, silently, with every cell still green
	// because the cert cell mints the smallest certificate that exists.
	if !hasNotify(m, payload.IKEFragmentationSupported) {
		return fmt.Errorf("goldens: the responder does not advertise FRAGMENTATION_SUPPORTED; " +
			"veepin will not fragment its own IKE output against this peer, which puts certificate " +
			"authentication back on the oversized-datagram path")
	}
	// NAT detection is the other negotiated behaviour the client acts on: both
	// halves must be present or the client cannot tell it is behind a NAT and
	// will not move to UDP-encapsulated ESP on 4500.
	if !hasNotify(m, payload.NATDetectionSourceIP) || !hasNotify(m, payload.NATDetectionDestinationIP) {
		return fmt.Errorf("goldens: the responder sent an incomplete NAT_DETECTION pair")
	}
	return nil
}

func hasNotify(m *payload.Message, want payload.NotifyType) bool {
	for _, p := range m.FindAll(payload.TypeNotify) {
		n, err := payload.ParseNotify(p.Body)
		if err == nil && n.Type == want {
			return true
		}
	}
	return false
}
