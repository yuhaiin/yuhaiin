package nebula

// Handshake framing and identity checking.
//
// The Noise exchange in noise.go establishes keys; this file decides who the
// peer is. Each Noise message carries a protobuf payload holding the sender's
// certificate and its chosen tunnel index, and the certificate is what binds a
// static key to an overlay address.
//
// The certificate arrives with its public key stripped, because Noise already
// transmitted the static key. Restoring it from the Noise state before
// verifying is not a convenience — it is the step that ties the two together.
// Without it a peer could present someone else's certificate, and the signature
// would still check out; the tunnel would then be keyed to one identity while
// claiming the address of another.

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"time"
)

// Field numbers for NebulaHandshake.
const fieldHandshakeDetails = 1

// Field numbers for NebulaHandshakeDetails. Numbers 6 and 7 are reserved in
// nebula for a work-in-progress feature, and 4 held a cookie that no released
// version ever populated.
const (
	fieldHSCert           = 1
	fieldHSInitiatorIndex = 2
	fieldHSResponderIndex = 3
	fieldHSTime           = 5
	fieldHSCertVersion    = 8
)

// certVersion1 is the certificate format veepin implements. It is advertised so
// a peer that supports several can pick this one.
const certVersion1 = 1

var (
	errHandshakePayload = errors.New("nebula: malformed handshake payload")
	// ErrPeerRejected reports a peer whose certificate did not verify.
	ErrPeerRejected = errors.New("nebula: peer certificate rejected")
)

// handshakePayload is the protobuf body of a handshake message.
type handshakePayload struct {
	Cert           []byte
	InitiatorIndex uint32
	ResponderIndex uint32
	Time           uint64
	CertVersion    uint32
}

func (p handshakePayload) marshal() []byte {
	var details []byte
	if len(p.Cert) > 0 {
		details = appendBytes(details, fieldHSCert, p.Cert)
	}
	if p.InitiatorIndex != 0 {
		details = appendUvarintField(details, fieldHSInitiatorIndex, uint64(p.InitiatorIndex))
	}
	if p.ResponderIndex != 0 {
		details = appendUvarintField(details, fieldHSResponderIndex, uint64(p.ResponderIndex))
	}
	if p.Time != 0 {
		details = appendUvarintField(details, fieldHSTime, p.Time)
	}
	if p.CertVersion != 0 {
		details = appendUvarintField(details, fieldHSCertVersion, uint64(p.CertVersion))
	}
	return appendBytes(nil, fieldHandshakeDetails, details)
}

func parseHandshakePayload(b []byte) (handshakePayload, error) {
	var p handshakePayload
	for len(b) > 0 {
		field, wire, rest, err := consumeTag(b)
		if err != nil {
			return p, errHandshakePayload
		}
		b = rest
		if field == fieldHandshakeDetails && wire == wireBytes {
			body, rest, err := consumeBytes(b)
			if err != nil {
				return p, errHandshakePayload
			}
			b = rest
			if err := p.parseDetails(body); err != nil {
				return p, err
			}
			continue
		}
		if b, err = skipField(wire, b); err != nil {
			return p, errHandshakePayload
		}
	}
	return p, nil
}

func (p *handshakePayload) parseDetails(b []byte) error {
	for len(b) > 0 {
		field, wire, rest, err := consumeTag(b)
		if err != nil {
			return errHandshakePayload
		}
		b = rest

		switch field {
		case fieldHSCert:
			v, rest, err := bytesField(wire, b)
			if err != nil {
				return errHandshakePayload
			}
			p.Cert = append([]byte(nil), v...)
			b = rest
		case fieldHSInitiatorIndex, fieldHSResponderIndex, fieldHSTime, fieldHSCertVersion:
			if wire != wireVarint {
				return errHandshakePayload
			}
			v, rest, err := consumeVarint(b)
			if err != nil {
				return errHandshakePayload
			}
			b = rest
			switch field {
			case fieldHSInitiatorIndex:
				p.InitiatorIndex = uint32(v)
			case fieldHSResponderIndex:
				p.ResponderIndex = uint32(v)
			case fieldHSTime:
				p.Time = v
			case fieldHSCertVersion:
				p.CertVersion = uint32(v)
			}
		default:
			if b, err = skipField(wire, b); err != nil {
				return errHandshakePayload
			}
		}
	}
	return nil
}

// Identity is a host's own credentials.
type Identity struct {
	Cert *Certificate
	Key  *ecdh.PrivateKey
	// wire is the certificate as sent in handshakes, public key elided.
	wire []byte
}

// NewIdentity pairs a certificate with the private key it is bound to.
func NewIdentity(c *Certificate, key *ecdh.PrivateKey) (*Identity, error) {
	if c.Curve != Curve25519 {
		return nil, fmt.Errorf("nebula: certificate uses %v: %w", c.Curve, ErrUnsupportedCurve)
	}
	// A certificate paired with the wrong key produces a tunnel that keys
	// correctly and then fails to verify on the far side, which is a confusing
	// way to learn about a configuration mistake.
	if pub := key.PublicKey().Bytes(); len(c.PublicKey) != len(pub) || string(c.PublicKey) != string(pub) {
		return nil, errors.New("nebula: private key does not match the certificate's public key")
	}
	return &Identity{Cert: c, Key: key, wire: c.MarshalForHandshakes()}, nil
}

// handshakeConfig is what both roles need to run an exchange.
type handshakeConfig struct {
	cipher   noiseCipher
	identity *Identity
	pool     *CAPool
	now      func() time.Time
	// eph pins the ephemeral keypair for a deterministic exchange. Tests set it;
	// production leaves it nil and each handshake generates its own. It is a key
	// rather than an io.Reader because Go 1.26's cryptocustomrand makes crypto
	// APIs ignore a caller-supplied reader -- see noise.go generateEphemeral.
	eph *ecdh.PrivateKey
}

func (c *handshakeConfig) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// verifyPeer restores the elided public key and checks the certificate against
// the trusted CAs, returning the peer's identity.
func (c *handshakeConfig) verifyPeer(raw []byte, staticKey []byte) (*Certificate, error) {
	peer, err := UnmarshalCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPeerRejected, err)
	}
	if len(peer.PublicKey) != 0 {
		// The key is supposed to be elided. A peer that sends one is either
		// buggy or trying to have the signature cover a key different from the
		// one Noise authenticated.
		return nil, fmt.Errorf("%w: certificate carries a public key, which handshakes must elide", ErrPeerRejected)
	}
	peer.PublicKey = append([]byte(nil), staticKey...)

	if _, err := c.pool.Verify(peer, c.clock()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPeerRejected, err)
	}
	if _, ok := peer.Address(); !ok {
		return nil, fmt.Errorf("%w: certificate %q carries no overlay address", ErrPeerRejected, peer.Name)
	}
	return peer, nil
}

// initiatorHandshake is an exchange in progress on the initiating side.
type initiatorHandshake struct {
	cfg        *handshakeConfig
	noise      *noiseHandshake
	localIndex uint32
}

// initiate produces the first handshake datagram.
func (c *handshakeConfig) initiate() (*initiatorHandshake, []byte, error) {
	localIndex, err := newLocalIndex()
	if err != nil {
		return nil, nil, err
	}
	hs := &initiatorHandshake{
		cfg:        c,
		noise:      newNoiseHandshake(c.cipher, true, c.identity.Key),
		localIndex: localIndex,
	}

	payload := handshakePayload{
		Cert:           c.identity.wire,
		InitiatorIndex: localIndex,
		Time:           uint64(c.clock().UnixNano()),
		CertVersion:    certVersion1,
	}.marshal()

	body, err := hs.noise.WriteMessage1(payload, c.ephemeral())
	if err != nil {
		return nil, nil, err
	}

	// The remote index is not known yet, so it is zero on the first message.
	h := header{
		Version:        headerVersion,
		Type:           typeHandshake,
		Subtype:        subTypeHandshakeIXPSK0,
		MessageCounter: 1,
	}
	return hs, append(h.encode(nil), body...), nil
}

// ephemeral is the fixed ephemeral keypair a test pinned, or nil to have the
// handshake generate its own from crypto/rand.
func (c *handshakeConfig) ephemeral() *ecdh.PrivateKey { return c.eph }

// respond consumes an initiator's message and produces the reply plus the
// established tunnel. The responder finishes the IX pattern, so it has keys as
// soon as it has written message two.
func (c *handshakeConfig) respond(pkt []byte) ([]byte, *tunnel, error) {
	h, err := parseHeader(pkt)
	if err != nil {
		return nil, nil, err
	}
	if h.Type != typeHandshake {
		return nil, nil, fmt.Errorf("nebula: expected a handshake, got %v", h.Type)
	}

	noiseHS := newNoiseHandshake(c.cipher, false, c.identity.Key)
	payloadBytes, err := noiseHS.ReadMessage1(pkt[headerLen:])
	if err != nil {
		return nil, nil, err
	}
	payload, err := parseHandshakePayload(payloadBytes)
	if err != nil {
		return nil, nil, err
	}
	if payload.InitiatorIndex == 0 {
		return nil, nil, fmt.Errorf("%w: initiator sent no tunnel index", errHandshake)
	}

	peer, err := c.verifyPeer(payload.Cert, noiseHS.PeerStatic())
	if err != nil {
		return nil, nil, err
	}

	localIndex, err := newLocalIndex()
	if err != nil {
		return nil, nil, err
	}
	reply := handshakePayload{
		Cert:           c.identity.wire,
		InitiatorIndex: payload.InitiatorIndex,
		ResponderIndex: localIndex,
		Time:           uint64(c.clock().UnixNano()),
		CertVersion:    certVersion1,
	}.marshal()

	body, err := noiseHS.WriteMessage2(reply, c.ephemeral())
	if err != nil {
		return nil, nil, err
	}

	send, recv := noiseHS.Split()
	t, err := newTunnel(c.cipher, false, localIndex, payload.InitiatorIndex, send, recv, peer)
	if err != nil {
		return nil, nil, err
	}

	replyHeader := header{
		Version:        headerVersion,
		Type:           typeHandshake,
		Subtype:        subTypeHandshakeIXPSK0,
		RemoteIndex:    payload.InitiatorIndex,
		MessageCounter: 2,
	}
	return append(replyHeader.encode(nil), body...), t, nil
}

// complete consumes the responder's reply on the initiating side.
func (hs *initiatorHandshake) complete(pkt []byte) (*tunnel, error) {
	h, err := parseHeader(pkt)
	if err != nil {
		return nil, err
	}
	if h.Type != typeHandshake {
		return nil, fmt.Errorf("nebula: expected a handshake, got %v", h.Type)
	}

	payloadBytes, err := hs.noise.ReadMessage2(pkt[headerLen:])
	if err != nil {
		return nil, err
	}
	payload, err := parseHandshakePayload(payloadBytes)
	if err != nil {
		return nil, err
	}
	if payload.ResponderIndex == 0 {
		return nil, fmt.Errorf("%w: responder sent no tunnel index", errHandshake)
	}

	peer, err := hs.cfg.verifyPeer(payload.Cert, hs.noise.PeerStatic())
	if err != nil {
		return nil, err
	}

	send, recv := hs.noise.Split()
	return newTunnel(hs.cfg.cipher, true, hs.localIndex, payload.ResponderIndex, send, recv, peer)
}
