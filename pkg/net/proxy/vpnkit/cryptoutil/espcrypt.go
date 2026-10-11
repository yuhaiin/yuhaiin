package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"slices"
)

// Inbound reject sentinels. Open runs on every datagram that reaches an SA,
// forged and replayed ones included, so its failures are pre-built: a flood of
// bad packets must cost no allocation per packet.
var (
	errAEADShort    = errors.New("cryptoutil: AEAD payload too short")
	errAEADOpen     = errors.New("cryptoutil: ESP AEAD authentication failed")
	errCBCShort     = errors.New("cryptoutil: CBC payload too short")
	errCBCIntegrity = errors.New("cryptoutil: ESP integrity check failed")
	errCBCAlign     = errors.New("cryptoutil: CBC ciphertext not block-aligned")
)

// ESPCrypter is an allocation-conscious cipher for the ESP data path. Unlike
// SKCipher (which rebuilds its cipher state on every call for handshake use),
// an ESPCrypter prepares its keyed cipher once and then seals/opens packets
// appending into a caller-supplied buffer, so the per-packet hot path performs
// no cipher construction and minimal allocation.
//
// A single ESPCrypter is intended to be driven by one goroutine at a time (one
// per SA direction), matching the userspace data-plane pump, which uses
// separate crypters for the inbound and outbound directions. It is not safe for
// concurrent use.
type ESPCrypter interface {
	// Overhead returns the number of octets Seal adds beyond the plaintext
	// (IV + ICV for AEAD; IV + MAC for CBC-ETM). Callers use it to size buffers.
	Overhead() int
	// BlockLen is the cipher block size for ESP trailer padding (1 for AEAD).
	BlockLen() int
	// Seal appends iv||ciphertext||icv for plaintext (authenticating aad) to
	// dst and returns the extended slice. aad is not encrypted.
	Seal(dst, aad, plaintext []byte) ([]byte, error)
	// Open verifies and decrypts ivCtIcv (authenticating aad), appending the
	// recovered plaintext to dst and returning the extended slice.
	Open(dst, aad, ivCtIcv []byte) ([]byte, error)
	// OpenInPlace is Open with the plaintext written over the ciphertext: the
	// result is a subslice of ivCtIcv, which is overwritten whether or not it
	// authenticates. It is what lets the inbound data path decrypt without
	// allocating, since the datagram's own buffer is the output.
	OpenInPlace(aad, ivCtIcv []byte) ([]byte, error)
}

// NewAESGCMESPCrypter builds a prepared AES-GCM-16 ESP crypter. keyBits is the
// AES key length (0 selects AES-256); encKey is the ESP encryption key followed
// by its 4-octet GCM salt (RFC 4106).
func NewAESGCMESPCrypter(keyBits int, encKey []byte) (ESPCrypter, error) {
	kl, err := aesKeyLen(keyBits)
	if err != nil {
		return nil, err
	}
	if len(encKey) < kl+4 {
		return nil, fmt.Errorf("cryptoutil: GCM key too short (%d, need %d)", len(encKey), kl+4)
	}
	block, err := aes.NewCipher(encKey[:kl])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return newESPAEAD(aead, encKey[kl:kl+4]), nil
}

// NewChaCha20Poly1305ESPCrypter builds a prepared ChaCha20-Poly1305 ESP crypter
// (RFC 7634). encKey is the 32-octet key followed by its 4-octet salt; the wire
// framing (8-octet IV, 16-octet tag, salt||IV nonce) matches AES-GCM-16, so it
// reuses the same prepared-AEAD crypter.
func NewChaCha20Poly1305ESPCrypter(encKey []byte) (ESPCrypter, error) {
	const kl = ChaCha20Poly1305KeySize
	if len(encKey) < kl+4 {
		return nil, fmt.Errorf("cryptoutil: ChaCha20 key too short (%d, need %d)", len(encKey), kl+4)
	}
	aead, err := NewChaCha20Poly1305(encKey[:kl])
	if err != nil {
		return nil, err
	}
	return newESPAEAD(aead, encKey[kl:kl+4]), nil
}

// NewAESCBCESPCrypter builds a prepared AES-CBC + HMAC (encrypt-then-MAC) ESP
// crypter. keyBits is the AES key length (0 selects AES-256); integ and integKey
// supply the MAC.
func NewAESCBCESPCrypter(keyBits int, encKey []byte, integ *Integrity, integKey []byte) (ESPCrypter, error) {
	kl, err := aesKeyLen(keyBits)
	if err != nil {
		return nil, err
	}
	if len(encKey) < kl {
		return nil, fmt.Errorf("cryptoutil: CBC key too short")
	}
	if integ == nil {
		return nil, fmt.Errorf("cryptoutil: CBC ESP requires an integrity transform")
	}
	block, err := aes.NewCipher(encKey[:kl])
	if err != nil {
		return nil, err
	}
	return &espCBC{block: block, integ: integ, integKey: integKey, mac: integ.newMAC(integKey)}, nil
}

// --- Generic AEAD ESP crypter (AES-GCM, ChaCha20-Poly1305) ---

// espAEAD is the prepared data-path crypter for any AEAD framed like AES-GCM-16
// (RFC 4106) or ChaCha20-Poly1305 (RFC 7634): a 4-octet implicit salt, an
// 8-octet explicit IV on the wire, and a 16-octet tag. It holds the keyed AEAD
// built once, so the per-packet path constructs nothing.
type espAEAD struct {
	aead  cipher.AEAD
	salt  [4]byte
	nonce []byte // reused 12-octet nonce buffer (single-goroutine per direction)
}

func newESPAEAD(aead cipher.AEAD, salt []byte) *espAEAD {
	g := &espAEAD{aead: aead}
	copy(g.salt[:], salt)
	return g
}

func (g *espAEAD) Overhead() int { return 8 + 16 } // explicit IV + tag
func (g *espAEAD) BlockLen() int { return 1 }

func (g *espAEAD) Seal(dst, aad, plaintext []byte) ([]byte, error) {
	// nonce = salt(4) || explicit-iv(8). A reused heap buffer avoids the escape
	// that passing a stack array through the AEAD interface would cause.
	if g.nonce == nil {
		g.nonce = make([]byte, 12)
		copy(g.nonce[0:4], g.salt[:])
	}
	if _, err := rand.Read(g.nonce[4:12]); err != nil {
		return nil, err
	}
	// Write the explicit IV first, then seal appending the ciphertext+tag
	// directly after it in dst.
	dst = append(dst, g.nonce[4:12]...)
	dst = g.aead.Seal(dst, g.nonce, plaintext, aad)
	return dst, nil
}

func (g *espAEAD) Open(dst, aad, ivCtIcv []byte) ([]byte, error) {
	if len(ivCtIcv) < 8+16 {
		return nil, errAEADShort
	}
	g.loadNonce(ivCtIcv)
	out, err := g.aead.Open(dst, g.nonce, ivCtIcv[8:], aad)
	if err != nil {
		return nil, errAEADOpen
	}
	return out, nil
}

// OpenInPlace decrypts over the ciphertext. The output starts exactly where
// the ciphertext does -- after the 8-octet explicit IV -- which is the one
// overlap cipher.AEAD permits: an output starting at the IV instead would be
// offset by eight octets and the AEAD would refuse it.
func (g *espAEAD) OpenInPlace(aad, ivCtIcv []byte) ([]byte, error) {
	if len(ivCtIcv) < 8+16 {
		return nil, errAEADShort
	}
	g.loadNonce(ivCtIcv)
	ct := ivCtIcv[8:]
	out, err := g.aead.Open(ct[:0], g.nonce, ct, aad)
	if err != nil {
		return nil, errAEADOpen
	}
	return out, nil
}

// loadNonce builds salt || explicit IV in the reused nonce buffer.
func (g *espAEAD) loadNonce(ivCtIcv []byte) {
	if g.nonce == nil {
		g.nonce = make([]byte, 12)
		copy(g.nonce[0:4], g.salt[:])
	}
	copy(g.nonce[4:12], ivCtIcv[:8])
}

// --- AES-CBC + HMAC ESP crypter (encrypt-then-MAC) ---

type espCBC struct {
	block    cipher.Block
	integ    *Integrity
	integKey []byte
	mac      hash.Hash // reused across calls (single-goroutine data path)

	// enc and dec are the CBC modes, built on first use and re-pointed at each
	// packet's IV. cipher.NewCBC* allocates the mode and a copy of the IV on
	// every call; crypto/tls keeps one per direction and calls SetIV for the
	// same reason. Nil when the block's mode does not offer SetIV, in which
	// case every packet builds its own, as before.
	enc, dec cbcMode

	// macBuf receives each ICV. A stack array here would escape through the
	// hash.Hash interface and cost an allocation per packet in each direction,
	// which is what it did.
	macBuf [64]byte
}

// cbcMode is a CBC BlockMode whose IV can be reset, which every mode
// crypto/cipher returns provides.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

func (c *espCBC) encrypter(iv []byte) cipher.BlockMode {
	if c.enc != nil {
		c.enc.SetIV(iv)
		return c.enc
	}
	m := cipher.NewCBCEncrypter(c.block, iv)
	c.enc, _ = m.(cbcMode)
	return m
}

func (c *espCBC) decrypter(iv []byte) cipher.BlockMode {
	if c.dec != nil {
		c.dec.SetIV(iv)
		return c.dec
	}
	m := cipher.NewCBCDecrypter(c.block, iv)
	c.dec, _ = m.(cbcMode)
	return m
}

func (c *espCBC) Overhead() int { return aes.BlockSize + c.integ.ICVLen }
func (c *espCBC) BlockLen() int { return aes.BlockSize }

func (c *espCBC) Seal(dst, aad, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cryptoutil: CBC plaintext not block-aligned (%d)", len(plaintext))
	}
	start := len(dst)
	// Reserve IV + ciphertext region, then fill. Grown in place when dst has
	// the room, which a caller-owned output buffer does.
	n := aes.BlockSize + len(plaintext)
	dst = slices.Grow(dst, n+c.integ.ICVLen)[:start+n]
	iv := dst[start : start+aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct := dst[start+aes.BlockSize:]
	c.encrypter(iv).CryptBlocks(ct, plaintext)
	// MAC covers aad || iv || ciphertext; append the truncated ICV.
	c.mac.Reset()
	c.mac.Write(aad)
	c.mac.Write(dst[start:]) // iv || ct
	icv := c.mac.Sum(c.macBuf[:0])[:c.integ.ICVLen]
	dst = append(dst, icv...)
	return dst, nil
}

func (c *espCBC) Open(dst, aad, ivCtIcv []byte) ([]byte, error) {
	iv, ct, err := c.verify(aad, ivCtIcv)
	if err != nil {
		return nil, err
	}
	start := len(dst)
	dst = slices.Grow(dst, len(ct))[:start+len(ct)]
	c.decrypter(iv).CryptBlocks(dst[start:], ct)
	return dst, nil
}

// OpenInPlace verifies, then decrypts the ciphertext over itself -- an exact
// overlap, which CBC decryption permits. The IV is read by SetIV before the
// first block is overwritten, and it is not part of ct, so in-place decryption
// cannot clobber it.
func (c *espCBC) OpenInPlace(aad, ivCtIcv []byte) ([]byte, error) {
	iv, ct, err := c.verify(aad, ivCtIcv)
	if err != nil {
		return nil, err
	}
	c.decrypter(iv).CryptBlocks(ct, ct)
	return ct, nil
}

// verify checks the ICV over aad || iv || ciphertext before anything is
// decrypted, and splits out the IV and ciphertext.
func (c *espCBC) verify(aad, ivCtIcv []byte) (iv, ct []byte, err error) {
	if len(ivCtIcv) < aes.BlockSize+c.integ.ICVLen {
		return nil, nil, errCBCShort
	}
	icv := ivCtIcv[len(ivCtIcv)-c.integ.ICVLen:]
	rest := ivCtIcv[:len(ivCtIcv)-c.integ.ICVLen]
	c.mac.Reset()
	c.mac.Write(aad)
	c.mac.Write(rest)
	want := c.mac.Sum(c.macBuf[:0])[:c.integ.ICVLen]
	if subtle.ConstantTimeCompare(want, icv) != 1 {
		return nil, nil, errCBCIntegrity
	}
	iv, ct = rest[:aes.BlockSize], rest[aes.BlockSize:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, nil, errCBCAlign
	}
	return iv, ct, nil
}
