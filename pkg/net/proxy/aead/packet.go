package aead

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func encodePacket(dst []byte, data []byte, auth cipher.AEAD) []byte {
	nonce := dst[:auth.NonceSize()]

	_, _ = io.ReadFull(rand.Reader, nonce)

	cryptext := auth.Seal(dst[auth.NonceSize():auth.NonceSize()],
		nonce, data, nil)

	return dst[:auth.NonceSize()+len(cryptext)]
}

func decodePacket(data []byte, auth cipher.AEAD) ([]byte, error) {
	nonce := data[:auth.NonceSize()]
	cryptext := data[auth.NonceSize():]
	return auth.Open(cryptext[:0], nonce, cryptext, nil)
}

type authPacketConn struct {
	net.PacketConn

	aead cipher.AEAD
}

func NewAuthPacketConn(local net.PacketConn, aead cipher.AEAD) *authPacketConn {
	return &authPacketConn{PacketConn: local, aead: aead}
}

func (s *authPacketConn) headerSize() int {
	return s.aead.NonceSize() + s.aead.Overhead()
}

func (s *authPacketConn) WriteTo(p []byte, addr net.Addr) (_ int, err error) {
	if len(p) > nat.MaxSegmentSize-s.headerSize() {
		return 0, fmt.Errorf("packet too large: %d > %d", len(p), nat.MaxSegmentSize)
	}

	buf := pool.GetBytes(len(p) + s.headerSize())
	defer pool.PutBytes(buf)

	cryptext := encodePacket(buf, p, s.aead)

	_, err = s.PacketConn.WriteTo(cryptext, addr)
	if err != nil {
		return 0, fmt.Errorf("write to remote failed: %w", err)
	}

	return len(p), nil
}

func (s *authPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, fmt.Errorf("read from remote failed: %w", err)
	}

	if n < s.headerSize() {
		return 0, nil, fmt.Errorf("packet too small: %d < %d", n, s.headerSize())
	}

	plaintext, err := decodePacket(p[:n], s.aead)
	if err != nil {
		return 0, nil, fmt.Errorf("decode packet failed: %w", err)
	}

	return copy(p[0:], plaintext), addr, nil
}
