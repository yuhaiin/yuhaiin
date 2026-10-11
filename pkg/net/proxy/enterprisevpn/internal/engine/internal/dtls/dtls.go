// Package dtls implements the subset of DTLS 1.2 (RFC 6347) that the AnyConnect
// data channel needs: a pre-shared-key handshake with AES-GCM, in both the
// client and server roles.
//
// It is deliberately not a general-purpose DTLS stack. AnyConnect's
// PSK-NEGOTIATE mode derives the pre-shared key from the already-established
// CSTP/TLS session with an RFC 5705 exporter, so there are no certificates, no
// chain validation and no key exchange to negotiate — which removes most of what
// makes DTLS large. What remains is the record layer, the PSK handshake flights,
// and the reliability machinery DTLS needs because it runs over UDP:
// retransmission, fragmentation and reassembly, and replay detection.
//
// Only AEAD cipher suites are supported, so there is no CBC/MAC-then-encrypt
// path and none of the padding-oracle surface that comes with it. Everything is
// built on the standard library's AES-GCM, HMAC and SHA-2.
package dtls

import "fmt"

// Protocol versions, on the wire as 1's-complement of the TLS version.
const (
	version1_0 uint16 = 0xfeff
	version1_2 uint16 = 0xfefd
)

// Record content types (RFC 5246 section 6.2.1).
const (
	recordChangeCipherSpec uint8 = 20
	recordAlert            uint8 = 21
	recordHandshake        uint8 = 22
	recordApplicationData  uint8 = 23
)

// Handshake message types (RFC 5246 section 7.4, RFC 6347 section 4.3.2).
const (
	handshakeClientHello       uint8 = 1
	handshakeServerHello       uint8 = 2
	handshakeHelloVerifyReq    uint8 = 3
	handshakeCertificate       uint8 = 11
	handshakeServerKeyExchange uint8 = 12
	handshakeServerHelloDone   uint8 = 14
	handshakeClientKeyExchange uint8 = 16
	handshakeFinished          uint8 = 20
)

// Alert levels and the descriptions we send or recognise.
const (
	alertWarning uint8 = 1
	alertFatal   uint8 = 2

	alertCloseNotify          uint8 = 0
	alertHandshakeFailure     uint8 = 40
	alertDecryptError         uint8 = 51
	alertInternalError        uint8 = 80
	alertNoRenegotiation      uint8 = 100
	alertUnsupportedExtension uint8 = 110
)

// Cipher suites. The PSK AEAD suites are what AnyConnect negotiates; the ECDHE
// suite is what Fortinet's certificate-based DTLS uses. Which set a connection
// offers is decided by its configuration, not mixed: a PSK connection never
// offers ECDHE and vice versa, so neither protocol can be steered onto the
// other's key exchange.
const (
	tlsPSKWithAES256GCMSHA384        uint16 = 0x00a9
	tlsPSKWithAES128GCMSHA256        uint16 = 0x00a8
	tlsECDHEECDSAWithAES128GCMSHA256 uint16 = 0xc02b
)

// keyExchange is how a suite establishes the premaster secret.
type keyExchange int

const (
	kxPSK   keyExchange = iota // RFC 4279 pre-shared key
	kxECDHE                    // ephemeral ECDH with a certificate-signed key share
)

// suite describes one supported cipher suite.
type suite struct {
	id      uint16
	kx      keyExchange
	keyLen  int // AEAD key length in octets
	ivLen   int // implicit (salt) nonce length
	hash    hashID
	prfHash hashID
}

// hashID selects a digest for the PRF and the handshake transcript.
type hashID int

const (
	hashSHA256 hashID = iota
	hashSHA384
)

// pskSuites are the AnyConnect PSK suites, in preference order.
var pskSuites = []suite{
	{id: tlsPSKWithAES256GCMSHA384, kx: kxPSK, keyLen: 32, ivLen: 4, hash: hashSHA384, prfHash: hashSHA384},
	{id: tlsPSKWithAES128GCMSHA256, kx: kxPSK, keyLen: 16, ivLen: 4, hash: hashSHA256, prfHash: hashSHA256},
}

// ecdheSuites are the certificate-based suites Fortinet's DTLS uses. Only
// ECDHE-ECDSA is implemented, matching the ECDSA certificates these gateways
// present; adding ECDHE-RSA would be a second signature path and is deferred
// until a peer needs it.
var ecdheSuites = []suite{
	{id: tlsECDHEECDSAWithAES128GCMSHA256, kx: kxECDHE, keyLen: 16, ivLen: 4, hash: hashSHA256, prfHash: hashSHA256},
}

// suiteByID looks up a negotiated suite across both sets.
func suiteByID(id uint16) (suite, error) {
	for _, list := range [][]suite{pskSuites, ecdheSuites} {
		for _, s := range list {
			if s.id == id {
				return s, nil
			}
		}
	}
	return suite{}, fmt.Errorf("dtls: unsupported cipher suite %#04x", id)
}

// Fixed sizes.
const (
	recordHeaderLen    = 13 // type, version, epoch, sequence, length
	handshakeHeaderLen = 12 // type, length, message_seq, fragment_offset, fragment_length
	randomLen          = 32
	masterSecretLen    = 48
	verifyDataLen      = 12
	// explicitNonceLen is the per-record nonce GCM sends in the clear, ahead of
	// the ciphertext (RFC 5288).
	explicitNonceLen = 8
	// maxRecord bounds a single record's payload.
	maxRecord = 16384
)
