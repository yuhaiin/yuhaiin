package data

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"
	"sync/atomic"

	"github.com/xen0bit/veepin/internal/openvpn/keys"
)

// The wire layout of one AES-256-CBC data packet (crypto.c, openvpn_encrypt for
// a CBC cipher):
//
//	byte 0        opcode<<3 | key_id   (P_DATA_V2)
//	bytes 1..3    peer-id (24-bit, big-endian)
//	bytes 4..     HMAC over (IV || ciphertext), --auth digest size
//	next 16       CBC initialisation vector (random per packet)
//	then          AES-256-CBC ciphertext of: packet ID (4) || plaintext, PKCS#7 padded
//
// Unlike GCM this is encrypt-then-MAC with a separate HMAC, and the packet ID is
// inside the encryption rather than authenticated in the clear. The opcode/peer-id
// header is not authenticated (OpenVPN computes the HMAC before prepending it).

// CBCCipher seals and opens AES-256-CBC data packets for one direction pair. Like
// the GCM Cipher it is safe for concurrent use: the send counter is atomic and the
// replay window is locked.
type CBCCipher struct {
	encBlock cipher.Block
	decBlock cipher.Block
	encHMAC  []byte // digest-sized send HMAC key
	decHMAC  []byte // digest-sized receive HMAC key
	newHash  func() hash.Hash
	hashSize int

	header  [headerLen]byte
	counter atomic.Uint32

	mu     sync.Mutex
	replay replayWindow
}

// NewCBC builds a CBC cipher from derived keys, the --auth digest (its hash
// constructor and output size), the peer-id, and the key_id.
func NewCBC(k keys.CBCKeys, newHash func() hash.Hash, hashSize int, peerID uint32, keyID uint8) (*CBCCipher, error) {
	encBlock, err := aes.NewCipher(k.EncryptKey[:])
	if err != nil {
		return nil, fmt.Errorf("data: cbc aes: %w", err)
	}
	decBlock, err := aes.NewCipher(k.DecryptKey[:])
	if err != nil {
		return nil, fmt.Errorf("data: cbc aes: %w", err)
	}
	c := &CBCCipher{
		encBlock: encBlock,
		decBlock: decBlock,
		encHMAC:  append([]byte(nil), k.EncryptHMAC[:hashSize]...),
		decHMAC:  append([]byte(nil), k.DecryptHMAC[:hashSize]...),
		newHash:  newHash,
		hashSize: hashSize,
	}
	c.header = makeHeader(peerID, keyID)
	return c, nil
}

// Seal encrypts one plaintext into a wire CBC data packet: header || HMAC || IV
// || AES-256-CBC(packet_id || plaintext).
func (c *CBCCipher) Seal(plaintext []byte) ([]byte, error) {
	return c.seal(plaintext, 0)
}

// SealPadded is Seal with the plaintext extended to minInner octets of zero
// filler, which downstream flow shaping uses to hide an inner packet's size
// (dataplane/shape.go). The filler sits between the inner packet and the PKCS#7
// trailer, so the trailer stays valid and the receiver still delimits the real
// packet by the inner IP header's own length.
func (c *CBCCipher) SealPadded(plaintext []byte, minInner int) ([]byte, error) {
	return c.seal(plaintext, minInner)
}

func (c *CBCCipher) seal(plaintext []byte, minInner int) ([]byte, error) {
	id := c.counter.Add(1)
	if id == 0 {
		return nil, errCounterExhausted
	}

	// work = packet_id(4) || plaintext || shaping filler, PKCS#7 padded up to a
	// full block. work is freshly allocated, so the filler is already zero.
	plainLen := packetIDLen + max(len(plaintext), minInner)
	pad := aes.BlockSize - plainLen%aes.BlockSize // 1..BlockSize
	work := make([]byte, plainLen+pad)
	binary.BigEndian.PutUint32(work[:packetIDLen], id)
	copy(work[packetIDLen:], plaintext)
	for i := plainLen; i < len(work); i++ {
		work[i] = byte(pad)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("data: cbc iv: %w", err)
	}
	// Encrypt in place: CBC allows dst == src.
	cipher.NewCBCEncrypter(c.encBlock, iv).CryptBlocks(work, work)

	mac := hmac.New(c.newHash, c.encHMAC)
	mac.Write(iv)
	mac.Write(work)
	tag := mac.Sum(nil)

	out := make([]byte, 0, headerLen+c.hashSize+aes.BlockSize+len(work))
	out = append(out, c.header[:]...)
	out = append(out, tag...)
	out = append(out, iv...)
	out = append(out, work...)
	return out, nil
}

// Open authenticates and decrypts a wire CBC data packet, returning the
// plaintext. The HMAC is checked before decryption (encrypt-then-MAC), and the
// replay window is advanced only after both succeed. pkt is decrypted in place
// and must be caller-owned.
func (c *CBCCipher) Open(pkt []byte) ([]byte, error) {
	fixed := headerLen + c.hashSize + aes.BlockSize
	if len(pkt) < fixed+aes.BlockSize {
		return nil, errShort
	}
	tag := pkt[headerLen : headerLen+c.hashSize]
	iv := pkt[headerLen+c.hashSize : fixed]
	ct := pkt[fixed:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, errShort
	}

	mac := hmac.New(c.newHash, c.decHMAC)
	mac.Write(iv)
	mac.Write(ct)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, errAuth
	}

	cipher.NewCBCDecrypter(c.decBlock, iv).CryptBlocks(ct, ct)
	work, err := pkcs7Unpad(ct)
	if err != nil {
		return nil, err
	}
	if len(work) < packetIDLen {
		return nil, errShort
	}
	id := binary.BigEndian.Uint32(work[:packetIDLen])

	c.mu.Lock()
	ok := c.replay.accept(id)
	c.mu.Unlock()
	if !ok {
		return nil, errReplay
	}
	return work[packetIDLen:], nil
}

// pkcs7Unpad strips PKCS#7 padding from a block-aligned buffer. The HMAC has
// already authenticated the ciphertext, so a bad pad means a malformed peer, not
// an oracle target; it is still rejected.
func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return nil, errShort
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(b) {
		return nil, errShort
	}
	for _, x := range b[len(b)-pad:] {
		if int(x) != pad {
			return nil, errShort
		}
	}
	return b[:len(b)-pad], nil
}
