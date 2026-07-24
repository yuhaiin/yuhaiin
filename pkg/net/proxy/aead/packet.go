package aead

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

func encryptPacket(dst []byte, data []byte, auth cipher.AEAD) ([]byte, error) {
	nonce := dst[:auth.NonceSize()]
	encrypt := dst[auth.NonceSize():]

	if len(encrypt) < auth.Overhead()+len(data) {
		return nil, io.ErrShortBuffer
	}

	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("read nonce failed: %w", err)
	}

	encrypt = auth.Seal(encrypt[:0], nonce, data, nil)
	return dst[:auth.NonceSize()+len(encrypt)], nil
}

func decryptPacket(data []byte, auth cipher.AEAD) ([]byte, error) {
	if len(data) < auth.NonceSize()+auth.Overhead() {
		return nil, io.ErrShortBuffer
	}

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

func NewMultiAuthPacketConn(local net.PacketConn, aeads []cipher.AEAD) net.PacketConn {
	return &multiAuthPacketConn{PacketConn: local, aeads: aeads, selected: make(map[string]cipher.AEAD)}
}

type multiAuthPacketConn struct {
	net.PacketConn
	aeads    []cipher.AEAD
	mu       sync.RWMutex
	selected map[string]cipher.AEAD
}

func (s *multiAuthPacketConn) headerSize() int {
	if len(s.aeads) == 0 {
		return 0
	}
	return s.aeads[0].NonceSize() + s.aeads[0].Overhead()
}

func (s *multiAuthPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(s.aeads) == 0 {
		return 0, errors.New("no AEAD credentials configured")
	}
	aead := s.aeads[0]
	if key := packetAddressKey(addr); key != "" {
		s.mu.RLock()
		if selected, ok := s.selected[key]; ok {
			aead = selected
		}
		s.mu.RUnlock()
	}
	return (&authPacketConn{PacketConn: s.PacketConn, aead: aead}).WriteTo(p, addr)
}

func (s *multiAuthPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, err
	}
	for _, aead := range s.aeads {
		if n < aead.NonceSize()+aead.Overhead() {
			continue
		}
		// AEAD.Open is allowed to overwrite its destination even when
		// authentication fails. Keep the original ciphertext intact while
		// trying the remaining credentials.
		candidate := append([]byte(nil), p[:n]...)
		plaintext, decryptErr := decryptPacket(candidate, aead)
		if decryptErr == nil {
			if key := packetAddressKey(addr); key != "" {
				s.mu.Lock()
				s.selected[key] = aead
				s.mu.Unlock()
			}
			return copy(p, plaintext), addr, nil
		}
	}
	return 0, nil, errors.New("AEAD packet authentication failed")
}

func packetAddressKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.Network() + ":" + addr.String()
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

	cryptext, err := encryptPacket(buf, p, s.aead)
	if err != nil {
		return 0, fmt.Errorf("encrypt packet failed: %w, len: %d", err, len(p))
	}

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

	plaintext, err := decryptPacket(p[:n], s.aead)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt packet failed: %w, len: %d, from: %v", err, n, addr)
	}

	return copy(p[0:], plaintext), addr, nil
}
