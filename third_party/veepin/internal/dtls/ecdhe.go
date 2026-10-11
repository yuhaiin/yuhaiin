package dtls

// The certificate-based ECDHE key exchange, for Fortinet's DTLS data channel.
//
// This is the part a PSK handshake does not have: the server proves possession
// of its certificate's private key by signing an ephemeral ECDH public key, and
// the shared ECDH secret becomes the premaster. Only one curve and one signature
// algorithm are implemented — NIST P-256 and ECDSA-SHA256 — which is what these
// gateways present and keeps the surface small. AES-GCM, SHA-256 and the record
// layer are all shared with the PSK path.

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

// TLS elliptic-curve constants (RFC 4492).
const (
	ecCurveTypeNamedCurve uint8  = 3
	ecNamedCurveSecp256r1 uint16 = 23
)

// signatureAndHash for ecdsa_secp256r1_sha256: hash=sha256(4), signature=ecdsa(3).
const (
	sigHashSHA256 uint8 = 4
	sigAlgECDSA   uint8 = 3
)

// marshalCertificate renders a Certificate handshake body: a 3-octet-length list
// of 3-octet-length DER certificates.
func marshalCertificate(chain [][]byte) []byte {
	var list []byte
	for _, der := range chain {
		list = append(list, putUint24(len(der))...)
		list = append(list, der...)
	}
	out := putUint24(len(list))
	return append(out, list...)
}

// parseCertificate decodes a Certificate body into its DER entries.
func parseCertificate(b []byte) ([][]byte, error) {
	if len(b) < 3 {
		return nil, errors.New("dtls: Certificate too short")
	}
	total := int(uint24(b))
	b = b[3:]
	if total != len(b) {
		return nil, errors.New("dtls: Certificate list length mismatch")
	}
	var chain [][]byte
	for len(b) > 0 {
		if len(b) < 3 {
			return nil, errors.New("dtls: truncated Certificate entry")
		}
		n := int(uint24(b))
		b = b[3:]
		if n > len(b) {
			return nil, errors.New("dtls: Certificate entry overruns the message")
		}
		chain = append(chain, b[:n])
		b = b[n:]
	}
	if len(chain) == 0 {
		return nil, errors.New("dtls: empty Certificate")
	}
	return chain, nil
}

// ecdheServerParams is the signed part of the ECDHE ServerKeyExchange: the curve
// and the server's ephemeral public point, in the exact bytes that are signed.
func ecdheServerParams(pubkey []byte) []byte {
	out := []byte{ecCurveTypeNamedCurve}
	out = binary.BigEndian.AppendUint16(out, ecNamedCurveSecp256r1)
	out = append(out, byte(len(pubkey)))
	return append(out, pubkey...)
}

// signECDHE signs the ServerKeyExchange parameters with the certificate key. The
// signature covers clientRandom || serverRandom || ServerECDHParams (RFC 4492
// §5.4), which binds the ephemeral key to this specific handshake.
func signECDHE(key crypto.Signer, clientRand, serverRand, params []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(clientRand)
	h.Write(serverRand)
	h.Write(params)
	return key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
}

// marshalECDHEServerKeyExchange builds the ServerKeyExchange body: the signed
// curve/point parameters, the signature algorithm, and the signature.
func marshalECDHEServerKeyExchange(params, signature []byte) []byte {
	out := append([]byte(nil), params...)
	out = append(out, sigHashSHA256, sigAlgECDSA)
	out = binary.BigEndian.AppendUint16(out, uint16(len(signature)))
	return append(out, signature...)
}

// serverKeyExchangeECDHE is a parsed ServerKeyExchange.
type serverKeyExchangeECDHE struct {
	pubkey    []byte // the server's ephemeral EC point (0x04||X||Y)
	params    []byte // the exact ServerECDHParams bytes that were signed
	signature []byte
}

func parseECDHEServerKeyExchange(b []byte) (serverKeyExchangeECDHE, error) {
	var m serverKeyExchangeECDHE
	r := reader{b: b}
	curveType := r.bytes(1)
	named := r.uint16()
	pub := r.vector8()
	if r.err != nil {
		return m, fmt.Errorf("dtls: malformed ServerKeyExchange: %w", r.err)
	}
	if len(curveType) != 1 || curveType[0] != ecCurveTypeNamedCurve || named != ecNamedCurveSecp256r1 {
		return m, fmt.Errorf("dtls: unsupported ECDHE curve (type %v, id %#04x)", curveType, named)
	}
	m.pubkey = pub
	m.params = ecdheServerParams(pub)

	// The signature algorithm (hash, signature): read past it. We do not enforce
	// a particular value here because the signature is verified with the
	// certificate's key regardless, which is the check that matters.
	r.bytes(2)
	m.signature = r.vector16()
	if r.err != nil {
		return m, fmt.Errorf("dtls: malformed ServerKeyExchange signature: %w", r.err)
	}
	return m, nil
}

// verifyECDHESignature checks the ServerKeyExchange signature against the leaf
// certificate's public key. This is what proves the peer holds the certificate's
// private key, and it is verified even when chain validation is skipped.
func verifyECDHESignature(leafDER []byte, clientRand, serverRand []byte, m serverKeyExchangeECDHE) error {
	cert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("dtls: parsing server certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("dtls: server certificate is not ECDSA")
	}
	h := sha256.New()
	h.Write(clientRand)
	h.Write(serverRand)
	h.Write(m.params)
	if !ecdsa.VerifyASN1(pub, h.Sum(nil), m.signature) {
		return errors.New("dtls: ServerKeyExchange signature does not verify")
	}
	return nil
}

// marshalECDHEClientKeyExchange builds the ClientKeyExchange body: the client's
// ephemeral EC point.
func marshalECDHEClientKeyExchange(pubkey []byte) []byte {
	out := []byte{byte(len(pubkey))}
	return append(out, pubkey...)
}

func parseECDHEClientKeyExchange(b []byte) ([]byte, error) {
	r := reader{b: b}
	pub := r.vector8()
	if r.err != nil {
		return nil, fmt.Errorf("dtls: malformed ClientKeyExchange: %w", r.err)
	}
	return pub, nil
}

// newECDHEKey generates an ephemeral P-256 key and returns it with its public
// point in uncompressed form (0x04||X||Y).
func newECDHEKey() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// ecdhePremaster computes the ECDH shared secret from our private key and the
// peer's public point. For a NIST curve the secret is the X coordinate, which is
// exactly what TLS uses as the premaster (RFC 4492 §5.10).
func ecdhePremaster(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("dtls: peer ECDHE key: %w", err)
	}
	return priv.ECDH(pub)
}

// putUint24 encodes a length as three big-endian octets.
func putUint24(n int) []byte {
	return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
}
