package nebula

// Nebula certificates (version 1).
//
// Nebula's identity model is a small PKI rather than a pre-shared key: a CA
// signs one certificate per host, and that certificate carries the host's
// overlay IP and its group memberships *inside the signed payload*. A peer
// therefore does not assert its address during the handshake — it presents a
// certificate, and the address is whatever the CA said it was. This is what
// makes the mesh work without a central server arbitrating who is who.
//
// Two certificate versions exist. Version 1 is protobuf-serialised and IPv4
// only; version 2 is ASN.1 and adds IPv6. veepin implements version 1, which
// current nebula still issues on request (`nebula-cert ca -version 1`) and
// still accepts. That matches this implementation's IPv4-only overlay; adding
// version 2 is a self-contained follow-up that does not disturb the handshake
// or data path.
//
// The signature covers the marshalled details, and is verified by re-marshalling
// rather than by retaining the received bytes — see proto.go for why the encoder
// has to be byte-exact.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// certificateBanner is the PEM type nebula writes for version 1 certificates.
const certificateBanner = "NEBULA CERTIFICATE"

// Field numbers for RawNebulaCertificate.
const (
	fieldCertDetails   = 1
	fieldCertSignature = 2
)

// Field numbers for RawNebulaCertificateDetails.
const (
	fieldDetailsName      = 1
	fieldDetailsIps       = 2
	fieldDetailsSubnets   = 3
	fieldDetailsGroups    = 4
	fieldDetailsNotBefore = 5
	fieldDetailsNotAfter  = 6
	fieldDetailsPublicKey = 7
	fieldDetailsIsCA      = 8
	fieldDetailsIssuer    = 9
	fieldDetailsCurve     = 100
)

// Curve identifies the signing and Diffie-Hellman curve a certificate is bound
// to. veepin implements Curve25519 only; a P256 certificate is parsed so that
// the mismatch can be reported clearly rather than failing as a bad signature.
type Curve uint8

const (
	// Curve25519 pairs Ed25519 signatures with X25519 key agreement.
	Curve25519 Curve = 0
	// CurveP256 pairs ECDSA-P256 signatures with ECDH-P256 key agreement.
	CurveP256 Curve = 1
)

func (c Curve) String() string {
	switch c {
	case Curve25519:
		return "CURVE25519"
	case CurveP256:
		return "P256"
	default:
		return fmt.Sprintf("Curve(%d)", uint8(c))
	}
}

var (
	// ErrExpired reports a certificate outside its validity window.
	ErrExpired = errors.New("nebula: certificate expired")
	// ErrSignature reports a certificate whose signature does not verify.
	ErrSignature = errors.New("nebula: certificate signature is invalid")
	// ErrUnknownIssuer reports a certificate signed by a CA that is not trusted.
	ErrUnknownIssuer = errors.New("nebula: certificate issuer is not a trusted CA")
	// ErrUnsupportedCurve reports a certificate veepin cannot verify.
	ErrUnsupportedCurve = errors.New("nebula: only Curve25519 certificates are supported")
)

// Certificate is a parsed nebula certificate.
type Certificate struct {
	Name string
	// Networks are the overlay addresses this host may use, as address/prefix
	// pairs. The first is the host's own address.
	Networks []netip.Prefix
	// UnsafeNetworks are non-overlay routes the host claims to reach.
	UnsafeNetworks []netip.Prefix
	Groups         []string
	NotBefore      time.Time
	NotAfter       time.Time
	PublicKey      []byte
	IsCA           bool
	// Issuer is the SHA-256 fingerprint of the signing CA's certificate, empty
	// when the certificate is self-signed.
	Issuer    []byte
	Curve     Curve
	Signature []byte
}

// Address returns the host's own overlay address.
func (c *Certificate) Address() (netip.Addr, bool) {
	if len(c.Networks) == 0 {
		return netip.Addr{}, false
	}
	return c.Networks[0].Addr(), true
}

// marshalDetails encodes the signed portion of the certificate. Field order and
// zero-value omission here have to match protobuf-go exactly; see proto.go.
func (c *Certificate) marshalDetails(withPublicKey bool) []byte {
	var b []byte
	if c.Name != "" {
		b = appendString(b, fieldDetailsName, c.Name)
	}
	b = appendPackedUint32(b, fieldDetailsIps, prefixesToInts(c.Networks))
	b = appendPackedUint32(b, fieldDetailsSubnets, prefixesToInts(c.UnsafeNetworks))
	for _, g := range c.Groups {
		b = appendString(b, fieldDetailsGroups, g)
	}
	if !c.NotBefore.IsZero() {
		b = appendUvarintField(b, fieldDetailsNotBefore, uint64(c.NotBefore.Unix()))
	}
	if !c.NotAfter.IsZero() {
		b = appendUvarintField(b, fieldDetailsNotAfter, uint64(c.NotAfter.Unix()))
	}
	if withPublicKey && len(c.PublicKey) > 0 {
		b = appendBytes(b, fieldDetailsPublicKey, c.PublicKey)
	}
	if c.IsCA {
		b = appendUvarintField(b, fieldDetailsIsCA, 1)
	}
	if len(c.Issuer) > 0 {
		b = appendBytes(b, fieldDetailsIssuer, c.Issuer)
	}
	if c.Curve != Curve25519 {
		b = appendUvarintField(b, fieldDetailsCurve, uint64(c.Curve))
	}
	return b
}

// Marshal encodes the full certificate, signature included.
func (c *Certificate) Marshal() []byte {
	return c.marshal(true)
}

// MarshalForHandshakes encodes the certificate with the public key elided. The
// Noise handshake transmits the static key in its own right, so repeating it
// here would waste room in a datagram that has to fit in one MTU. The receiver
// puts the key back before checking the signature.
func (c *Certificate) MarshalForHandshakes() []byte {
	return c.marshal(false)
}

func (c *Certificate) marshal(withPublicKey bool) []byte {
	var b []byte
	b = appendBytes(b, fieldCertDetails, c.marshalDetails(withPublicKey))
	if len(c.Signature) > 0 {
		b = appendBytes(b, fieldCertSignature, c.Signature)
	}
	return b
}

// MarshalPEM encodes the certificate in the PEM form nebula reads from disk.
func (c *Certificate) MarshalPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: certificateBanner, Bytes: c.Marshal()})
}

// Fingerprint is the SHA-256 of the marshalled certificate, hex encoded. It is
// how a certificate names its issuer and how a CA is identified in config.
func (c *Certificate) Fingerprint() string {
	sum := sha256.Sum256(c.Marshal())
	return hex.EncodeToString(sum[:])
}

// CheckSignature reports whether the certificate is signed by the holder of key.
func (c *Certificate) CheckSignature(key []byte) bool {
	if c.Curve != Curve25519 || len(key) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(key, c.marshalDetails(true), c.Signature)
}

// Expired reports whether t falls outside the validity window.
func (c *Certificate) Expired(t time.Time) bool {
	return c.NotBefore.After(t) || c.NotAfter.Before(t)
}

// Sign fills in the signature using the CA's private key.
func (c *Certificate) Sign(key ed25519.PrivateKey) error {
	if c.Curve != Curve25519 {
		return ErrUnsupportedCurve
	}
	c.Signature = ed25519.Sign(key, c.marshalDetails(true))
	return nil
}

// UnmarshalCertificatePEM parses the PEM form, returning any trailing data so a
// file holding a chain can be read in a loop.
func UnmarshalCertificatePEM(b []byte) (*Certificate, []byte, error) {
	block, rest := pem.Decode(b)
	if block == nil {
		return nil, rest, errors.New("nebula: no PEM block found")
	}
	if block.Type != certificateBanner {
		// Version 2 certificates use a different banner, so name the reason
		// rather than reporting a parse failure.
		return nil, rest, fmt.Errorf("nebula: unsupported PEM block %q (veepin implements version 1 certificates)", block.Type)
	}
	c, err := UnmarshalCertificate(block.Bytes)
	if err != nil {
		return nil, rest, err
	}
	return c, rest, nil
}

// UnmarshalCertificate parses the protobuf form.
func UnmarshalCertificate(b []byte) (*Certificate, error) {
	c := &Certificate{}
	seenDetails := false
	for len(b) > 0 {
		field, wire, rest, err := consumeTag(b)
		if err != nil {
			return nil, err
		}
		b = rest
		switch {
		case field == fieldCertDetails && wire == wireBytes:
			body, rest, err := consumeBytes(b)
			if err != nil {
				return nil, err
			}
			b = rest
			if err := c.unmarshalDetails(body); err != nil {
				return nil, err
			}
			seenDetails = true
		case field == fieldCertSignature && wire == wireBytes:
			body, rest, err := consumeBytes(b)
			if err != nil {
				return nil, err
			}
			b = rest
			c.Signature = append([]byte(nil), body...)
		default:
			if b, err = skipField(wire, b); err != nil {
				return nil, err
			}
		}
	}
	if !seenDetails {
		return nil, errors.New("nebula: certificate has no details")
	}
	return c, nil
}

func (c *Certificate) unmarshalDetails(b []byte) error {
	var ips, subnets []uint32
	for len(b) > 0 {
		field, wire, rest, err := consumeTag(b)
		if err != nil {
			return err
		}
		b = rest

		// A known field number carrying an unexpected wire type is a peer
		// protocol violation, not something to skip past silently.
		switch field {
		case fieldDetailsName:
			v, rest, err := bytesField(wire, b)
			if err != nil {
				return err
			}
			c.Name, b = string(v), rest
		case fieldDetailsIps, fieldDetailsSubnets:
			v, rest, err := bytesField(wire, b)
			if err != nil {
				return err
			}
			parsed, err := consumePackedUint32(v)
			if err != nil {
				return err
			}
			if field == fieldDetailsIps {
				ips = parsed
			} else {
				subnets = parsed
			}
			b = rest
		case fieldDetailsGroups:
			v, rest, err := bytesField(wire, b)
			if err != nil {
				return err
			}
			c.Groups = append(c.Groups, string(v))
			b = rest
		case fieldDetailsNotBefore, fieldDetailsNotAfter, fieldDetailsIsCA, fieldDetailsCurve:
			if wire != wireVarint {
				return errProto
			}
			v, rest, err := consumeVarint(b)
			if err != nil {
				return err
			}
			b = rest
			switch field {
			case fieldDetailsNotBefore:
				c.NotBefore = time.Unix(int64(v), 0)
			case fieldDetailsNotAfter:
				c.NotAfter = time.Unix(int64(v), 0)
			case fieldDetailsIsCA:
				c.IsCA = v != 0
			case fieldDetailsCurve:
				c.Curve = Curve(v)
			}
		case fieldDetailsPublicKey, fieldDetailsIssuer:
			v, rest, err := bytesField(wire, b)
			if err != nil {
				return err
			}
			if field == fieldDetailsPublicKey {
				c.PublicKey = append([]byte(nil), v...)
			} else {
				c.Issuer = append([]byte(nil), v...)
			}
			b = rest
		default:
			if b, err = skipField(wire, b); err != nil {
				return err
			}
		}
	}

	if err := intsToPrefixes(ips, &c.Networks); err != nil {
		return errors.New("nebula: certificate networks are malformed")
	}
	if err := intsToPrefixes(subnets, &c.UnsafeNetworks); err != nil {
		return errors.New("nebula: certificate unsafe networks are malformed")
	}
	return nil
}

// bytesField reads a length-delimited value, rejecting a wire type mismatch.
func bytesField(wire uint64, b []byte) ([]byte, []byte, error) {
	if wire != wireBytes {
		return nil, nil, errProto
	}
	return consumeBytes(b)
}

// prefixesToInts flattens address/mask pairs into the big-endian 32-bit words
// version 1 stores them as.
func prefixesToInts(ps []netip.Prefix) []uint32 {
	out := make([]uint32, 0, len(ps)*2)
	for _, p := range ps {
		addr := p.Addr().As4()
		mask := ^uint32(0) << (32 - p.Bits())
		out = append(out,
			uint32(addr[0])<<24|uint32(addr[1])<<16|uint32(addr[2])<<8|uint32(addr[3]),
			mask,
		)
	}
	return out
}

// intsToPrefixes rebuilds prefixes from address/mask pairs. Masks are required
// to be contiguous, which every mask nebula emits is.
func intsToPrefixes(v []uint32, out *[]netip.Prefix) error {
	if len(v)%2 != 0 {
		return errProto
	}
	for i := 0; i < len(v); i += 2 {
		addr := netip.AddrFrom4([4]byte{
			byte(v[i] >> 24), byte(v[i] >> 16), byte(v[i] >> 8), byte(v[i]),
		})
		mask := v[i+1]
		bits := 0
		for bits < 32 && mask&(1<<(31-uint(bits))) != 0 {
			bits++
		}
		if mask<<uint(bits) != 0 {
			return errProto
		}
		*out = append(*out, netip.PrefixFrom(addr, bits))
	}
	return nil
}
