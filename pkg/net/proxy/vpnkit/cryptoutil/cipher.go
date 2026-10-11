package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
)

// SKCipher protects the encrypted (SK) payload. It handles both AEAD ciphers
// (AES-GCM, ChaCha20-Poly1305) and the classic encrypt-then-MAC construction
// (AES-CBC + HMAC). The interface abstracts over both so the message layer is
// agnostic to which suite was negotiated.
//
// Layout of the SK payload body (RFC 7296 section 3.14):
//
//	[ IV | ciphertext(padded) | ICV ]
//
// For AEAD, IV is the explicit nonce portion and ICV is the auth tag. The AAD
// covers the IKE header and all preceding payload headers up to and including
// the SK generic header.
type SKCipher interface {
	// KeyLen is the encryption key length in bytes.
	KeyLen() int
	// IVLen is the length of the per-message IV/nonce written on the wire.
	IVLen() int
	// ICVLen is the length of the integrity tag/MAC appended after ciphertext.
	ICVLen() int
	// BlockLen is the cipher block size for padding; 1 for stream/AEAD.
	BlockLen() int
	// AEAD reports whether integrity is provided by the cipher itself.
	AEAD() bool

	// Seal encrypts plaintext and returns iv||ciphertext||icv. aad is the
	// authenticated-but-not-encrypted prefix (IKE header .. SK header).
	Seal(encKey, integKey, aad, plaintext []byte) ([]byte, error)
	// Open verifies and decrypts. For non-AEAD, integ is checked over
	// aad||iv||ciphertext before decryption (encrypt-then-MAC).
	Open(encKey, integKey, aad, ivCtIcv []byte) (plaintext []byte, err error)
}

// SKParams bundles a negotiated cipher and (for non-AEAD) integrity transform.
type SKParams struct {
	Cipher SKCipher
	Integ  *Integrity // nil for AEAD
}

// aesKeyLen validates an AES key length in bits, mapping 0 to the 256-bit
// default, and returns it in bytes.
func aesKeyLen(keyBits int) (int, error) {
	kl := keyBits / 8
	if kl == 0 {
		kl = 32
	}
	if kl != 16 && kl != 24 && kl != 32 {
		return 0, fmt.Errorf("cryptoutil: bad AES key length %d bits", keyBits)
	}
	return kl, nil
}

// NewAESGCMSKCipher returns an AES-GCM-16 SK cipher (RFC 5282) for the given
// key length in bits; 0 selects AES-256.
func NewAESGCMSKCipher(keyBits int) (SKCipher, error) {
	kl, err := aesKeyLen(keyBits)
	if err != nil {
		return nil, err
	}
	return &aeadCipher{keyLen: kl, mkAEAD: newGCMAEAD}, nil
}

// NewChaCha20Poly1305SKCipher returns a ChaCha20-Poly1305 SK cipher (RFC 7634).
// Its wire framing is identical to AES-GCM-16 — a 4-octet salt in the trailing
// key material, an 8-octet explicit IV and a 16-octet tag — so it shares the
// generic AEAD implementation; only the key is fixed at 256 bits and there is no
// key-length attribute to negotiate.
func NewChaCha20Poly1305SKCipher() (SKCipher, error) {
	return &aeadCipher{keyLen: ChaCha20Poly1305KeySize, mkAEAD: NewChaCha20Poly1305}, nil
}

// newGCMAEAD builds an AES-GCM AEAD from a bare AES key (no salt).
func newGCMAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewAESCBCSKCipher returns an AES-CBC SK cipher for the given key length in
// bits; 0 selects AES-256. Integrity is supplied separately by an Integrity
// transform, and callers must route Seal/Open through SealETM/OpenETM.
func NewAESCBCSKCipher(keyBits int) (SKCipher, error) {
	kl, err := aesKeyLen(keyBits)
	if err != nil {
		return nil, err
	}
	return &cbcCipher{keyLen: kl}, nil
}

// --- Generic AEAD SK cipher (AES-GCM RFC 5282, ChaCha20-Poly1305 RFC 7634) ---

// aeadCipher is the SK cipher for any AEAD framed like AES-GCM-16: the trailing
// 4 octets of the SK_e material are an implicit salt, the 8-octet explicit IV is
// on the wire, and the salt||IV form the 12-octet nonce. mkAEAD builds the AEAD
// from the leading keyLen octets, so AES-GCM and ChaCha20-Poly1305 differ only
// in that constructor and their key length.
type aeadCipher struct {
	keyLen int
	mkAEAD func(key []byte) (cipher.AEAD, error)
}

func (c *aeadCipher) KeyLen() int   { return c.keyLen + 4 } // + 4-octet salt
func (c *aeadCipher) IVLen() int    { return 8 }            // explicit nonce
func (c *aeadCipher) ICVLen() int   { return 16 }
func (c *aeadCipher) BlockLen() int { return 1 }
func (c *aeadCipher) AEAD() bool    { return true }

func (c *aeadCipher) aead(key []byte) (cipher.AEAD, []byte, error) {
	// The last 4 octets of the SK_e material are the salt (RFC 5282 §4,
	// RFC 7634 §2).
	salt := key[c.keyLen : c.keyLen+4]
	a, err := c.mkAEAD(key[:c.keyLen])
	if err != nil {
		return nil, nil, err
	}
	return a, salt, nil
}

func (c *aeadCipher) Seal(encKey, _ /*integ*/, aad, plaintext []byte) ([]byte, error) {
	a, salt, err := c.aead(encKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, c.IVLen())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	nonce := append(append([]byte(nil), salt...), iv...)
	ct := a.Seal(nil, nonce, plaintext, aad)
	out := append(append([]byte(nil), iv...), ct...)
	return out, nil
}

func (c *aeadCipher) Open(encKey, _ /*integ*/, aad, ivCtIcv []byte) ([]byte, error) {
	if len(ivCtIcv) < c.IVLen()+c.ICVLen() {
		return nil, fmt.Errorf("cryptoutil: AEAD payload too short")
	}
	a, salt, err := c.aead(encKey)
	if err != nil {
		return nil, err
	}
	iv := ivCtIcv[:c.IVLen()]
	ct := ivCtIcv[c.IVLen():]
	nonce := append(append([]byte(nil), salt...), iv...)
	return a.Open(nil, nonce, ct, aad)
}

// --- AES-CBC + HMAC (encrypt-then-MAC) ---

type cbcCipher struct{ keyLen int }

func (c *cbcCipher) KeyLen() int   { return c.keyLen }
func (c *cbcCipher) IVLen() int    { return aes.BlockSize }
func (c *cbcCipher) ICVLen() int   { return 0 } // provided by the Integrity transform
func (c *cbcCipher) BlockLen() int { return aes.BlockSize }
func (c *cbcCipher) AEAD() bool    { return false }

// cbcInteg is set by the message layer via SealCBC/OpenCBC helpers below; to
// keep the SKCipher interface uniform we thread the integrity MAC through the
// integKey argument and a package-level helper. For CBC, Seal/Open expect the
// integ transform to be supplied out-of-band through SKParams, so these two
// methods panic if called directly; the message layer always routes CBC via
// SealETM/OpenETM.
func (c *cbcCipher) Seal(encKey, integKey, aad, plaintext []byte) ([]byte, error) {
	return nil, fmt.Errorf("cryptoutil: CBC requires SealETM")
}

func (c *cbcCipher) Open(encKey, integKey, aad, ivCtIcv []byte) ([]byte, error) {
	return nil, fmt.Errorf("cryptoutil: CBC requires OpenETM")
}

// SealETM performs AES-CBC encrypt-then-MAC. It returns iv||ciphertext||icv.
// The plaintext MUST already be padded to a multiple of the block size by the
// caller (the SK and ESP layers own their respective padding schemes).
func (c *cbcCipher) SealETM(encKey, integKey, aad, plaintext []byte, integ *Integrity) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cryptoutil: CBC plaintext not block-aligned (%d)", len(plaintext))
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	padded := plaintext
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	// MAC covers aad || iv || ciphertext.
	macInput := make([]byte, 0, len(aad)+len(iv)+len(ct))
	macInput = append(macInput, aad...)
	macInput = append(macInput, iv...)
	macInput = append(macInput, ct...)
	icv := integ.Sum(integKey, macInput)
	out := append(append(append([]byte(nil), iv...), ct...), icv...)
	return out, nil
}

// OpenETM verifies then decrypts an AES-CBC encrypt-then-MAC SK body.
func (c *cbcCipher) OpenETM(encKey, integKey, aad, ivCtIcv []byte, integ *Integrity) ([]byte, error) {
	if len(ivCtIcv) < aes.BlockSize+integ.ICVLen {
		return nil, fmt.Errorf("cryptoutil: CBC payload too short")
	}
	icv := ivCtIcv[len(ivCtIcv)-integ.ICVLen:]
	rest := ivCtIcv[:len(ivCtIcv)-integ.ICVLen]
	// Verify MAC before touching the ciphertext.
	macInput := make([]byte, 0, len(aad)+len(rest))
	macInput = append(macInput, aad...)
	macInput = append(macInput, rest...)
	want := integ.Sum(integKey, macInput)
	if subtle.ConstantTimeCompare(want, icv) != 1 {
		return nil, fmt.Errorf("cryptoutil: SK integrity check failed")
	}
	iv := rest[:aes.BlockSize]
	ct := rest[aes.BlockSize:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cryptoutil: CBC ciphertext not block-aligned")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	// The caller strips its own padding scheme (RFC 7296 for SK, RFC 4303 for
	// ESP); return the raw block-aligned plaintext.
	return pt, nil
}

// ensure hmac import is used even if only AEAD ciphers are exercised.
var _ = hmac.New
