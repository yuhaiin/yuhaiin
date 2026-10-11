package tlswrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// tls-crypt fixed sizes: HMAC-SHA256 tag, AES-256 key, and the CTR IV taken from
// the tag's first block.
const (
	cryptTagLen = sha256.Size // 32
	cryptKeyLen = 32          // AES-256
	cryptIVLen  = aes.BlockSize
	// cryptCipherOff is where the ciphertext begins: header | replay | tag.
	cryptReplayOff = headerLen
	cryptTagOff    = headerLen + replayLen
	cryptCipherOff = cryptTagOff + cryptTagLen
)

// cryptWrapper implements --tls-crypt: it authenticates the whole control packet
// with HMAC-SHA256 and encrypts the body with AES-256-CTR, using the first 16
// bytes of the tag as the CTR IV (a synthetic-IV construction, MAC-then-encrypt).
type cryptWrapper struct {
	sendBlock cipher.Block
	sendMAC   []byte
	recvBlock cipher.Block
	recvMAC   []byte

	sendID   counter
	recvSeen replayWindow
}

// NewCrypt builds a --tls-crypt wrapper. The client direction is always Inverse
// (send with key slot 1, receive with slot 0); pass that unless building the
// server side.
func NewCrypt(key *StaticKey, dir Direction) (Wrapper, error) {
	sendBlock, err := aes.NewCipher(key.cipherKey(dir.outSlot(), cryptKeyLen))
	if err != nil {
		return nil, fmt.Errorf("tlswrap: crypt send key: %w", err)
	}
	recvBlock, err := aes.NewCipher(key.cipherKey(dir.inSlot(), cryptKeyLen))
	if err != nil {
		return nil, fmt.Errorf("tlswrap: crypt recv key: %w", err)
	}
	return &cryptWrapper{
		sendBlock: sendBlock,
		sendMAC:   key.hmacKey(dir.outSlot(), cryptTagLen),
		recvBlock: recvBlock,
		recvMAC:   key.hmacKey(dir.inSlot(), cryptTagLen),
	}, nil
}

// Wrap produces: opcode | session_id | packet_id | net_time | HMAC | ciphertext,
// where the HMAC covers opcode | session_id | packet_id | net_time | plaintext
// body and its first 16 bytes seed the AES-256-CTR keystream over the body.
func (w *cryptWrapper) Wrap(pkt []byte) ([]byte, error) {
	if len(pkt) < headerLen {
		return nil, ErrShort
	}
	header := pkt[:headerLen]
	body := pkt[headerLen:]

	id := w.sendID.next()
	now := uint32(time.Now().Unix())
	var replay [replayLen]byte
	binary.BigEndian.PutUint32(replay[:pidLen], id)
	binary.BigEndian.PutUint32(replay[pidLen:], now)

	mac := hmac.New(sha256.New, w.sendMAC)
	mac.Write(header)
	mac.Write(replay[:])
	mac.Write(body)
	tag := mac.Sum(nil)

	out := make([]byte, cryptCipherOff+len(body))
	copy(out[:headerLen], header)
	copy(out[cryptReplayOff:], replay[:])
	copy(out[cryptTagOff:cryptCipherOff], tag)
	cipher.NewCTR(w.sendBlock, tag[:cryptIVLen]).XORKeyStream(out[cryptCipherOff:], body)
	return out, nil
}

// Unwrap decrypts the body, recomputes the HMAC over the recovered plaintext,
// and returns opcode | session_id | body on a match.
func (w *cryptWrapper) Unwrap(dg []byte) ([]byte, error) {
	if len(dg) < cryptCipherOff {
		return nil, ErrShort
	}
	header := dg[:headerLen]
	replay := dg[cryptReplayOff:cryptTagOff]
	tag := dg[cryptTagOff:cryptCipherOff]
	ct := dg[cryptCipherOff:]

	// Decrypt first (the tag is the synthetic IV), then authenticate the plaintext.
	body := make([]byte, len(ct))
	cipher.NewCTR(w.recvBlock, tag[:cryptIVLen]).XORKeyStream(body, ct)

	mac := hmac.New(sha256.New, w.recvMAC)
	mac.Write(header)
	mac.Write(replay)
	mac.Write(body)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, ErrAuth
	}
	if !w.recvSeen.accept(binary.BigEndian.Uint32(replay[:pidLen])) {
		return nil, ErrReplay
	}

	out := make([]byte, 0, headerLen+len(body))
	out = append(out, header...)
	out = append(out, body...)
	return out, nil
}
