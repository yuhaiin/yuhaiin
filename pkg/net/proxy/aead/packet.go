package aead

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func EncodePacket(w *pool.Buffer, addr net.Addr, buf []byte, auth cipher.AEAD) error {
	ad, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return fmt.Errorf("parse addr failed: %w", err)
	}

	_, _ = w.ReadFrom(io.LimitReader(rand.Reader, int64(auth.NonceSize())))

	tools.WriteAddr(ad, w)

	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	if auth == nil {
		return nil
	}

	w.Advance(auth.Overhead())

	nonce := w.Bytes()[:auth.NonceSize()]
	data := w.Bytes()[auth.NonceSize() : w.Len()-auth.Overhead()]
	cryptext := w.Bytes()[auth.NonceSize():]

	auth.Seal(cryptext[:0], nonce, data, nil)

	return nil
}

func MaxPacketHeaderSize(auth cipher.AEAD) int {
	return tools.MaxAddrLength + auth.NonceSize() + auth.Overhead()
}

func DecodePacket(r []byte, auth cipher.AEAD) ([]byte, error) {
	if len(r) < auth.NonceSize()+auth.Overhead() {
		return nil, fmt.Errorf("nonce with overhead is not enough")
	}

	nonce := r[:auth.NonceSize()]
	cryptext := r[auth.NonceSize():]
	r = r[auth.NonceSize() : len(r)-auth.Overhead()]

	var err error
	r, err = auth.Open(r[:0], nonce, cryptext, nil)
	if err != nil {
		return nil, err
	}

	return r, nil
}

type authPacketConn struct {
	net.PacketConn

	aead cipher.AEAD
}

func NewAuthPacketConn(local net.PacketConn, aead cipher.AEAD) *authPacketConn {
	return &authPacketConn{PacketConn: local, aead: aead}
}

func (s *authPacketConn) WriteTo(p []byte, addr net.Addr) (_ int, err error) {
	if len(p) > nat.MaxSegmentSize-MaxPacketHeaderSize(s.aead) {
		return 0, fmt.Errorf("packet too large: %d > %d", len(p), nat.MaxSegmentSize)
	}

	buf := pool.NewBufferSize(len(p) + MaxPacketHeaderSize(s.aead))
	defer buf.Reset()

	err = EncodePacket(buf, addr, p, s.aead)
	if err != nil {
		return 0, fmt.Errorf("encode packet failed: %w", err)
	}

	_, err = s.PacketConn.WriteTo(buf.Bytes(), addr)
	if err != nil {
		return 0, fmt.Errorf("write to remote failed: %w", err)
	}

	return len(p), nil
}

func (s *authPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, rawAddr, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, fmt.Errorf("read from remote failed: %w", err)
	}

	buf, err := DecodePacket(p[:n], s.aead)
	if err != nil {
		return 0, nil, fmt.Errorf("decode packet failed: %w", err)
	}

	return copy(p[0:], buf), rawAddr, nil
}
