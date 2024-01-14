package yuubinsya

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type authPacketConn struct {
	net.PacketConn
	tcp    net.Conn
	server net.Addr

	auth Auth

	prefix bool
}

func NewAuthPacketConn(local net.PacketConn, tcp net.Conn, target net.Addr, auth Auth, prefix bool) *authPacketConn {
	return &authPacketConn{local, tcp, target, auth, prefix}
}

func (s *authPacketConn) Close() error {
	if s.tcp != nil {
		s.tcp.Close()
	}
	return s.PacketConn.Close()
}

func (s *authPacketConn) WriteTo(p []byte, addr net.Addr) (_ int, err error) {
	return s.writeTo(p, addr, s.server)
}

func (s *authPacketConn) writeTo(p []byte, addr net.Addr, underlyingAddr net.Addr) (_ int, err error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	err = EncodePacket(buf, addr, p, s.auth, s.prefix)
	if err != nil {
		return 0, fmt.Errorf("encode packet failed: %w", err)
	}

	_, err = s.PacketConn.WriteTo(buf.Bytes(), underlyingAddr)
	if err != nil {
		return 0, fmt.Errorf("write to remote failed: %w", err)
	}

	return len(p), nil
}

func (s *authPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, _, err := s.readFrom(p)
	return n, addr, err
}

var ErrNet = errors.New("network error")

func (s *authPacketConn) readFrom(p []byte) (int, netapi.Address, net.Addr, error) {
	n, rawAddr, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w read from remote failed: %w", ErrNet, err)
	}
	buf, addr, err := DecodePacket(p[:n], s.auth, s.prefix)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("decode packet failed: %w", err)
	}

	return copy(p[0:], buf), addr, rawAddr, nil
}

func EncodePacket(w *bytes.Buffer, addr net.Addr, buf []byte, auth Auth, prefix bool) error {
	ad, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return fmt.Errorf("parse addr failed: %w", err)
	}

	if auth != nil {
		if auth.NonceSize() > 0 {
			_, err = w.Write(make([]byte, auth.NonceSize()))
			if err != nil {
				return err
			}

			_, err = rand.Read(w.Bytes())
			if err != nil {
				return err
			}
		}

		if auth.KeySize() > 0 {
			_, err = w.Write(auth.Key())
			if err != nil {
				return err
			}
		}
	}

	if prefix {
		_, err = w.Write([]byte{0, 0, 0})
		if err != nil {
			return err
		}
	}

	tools.ParseAddrWriter(ad, w)

	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	if auth == nil {
		return nil
	}

	w.Write(make([]byte, auth.Overhead()))

	if auth.NonceSize() > 0 {
		nonce := w.Bytes()[:auth.NonceSize()]
		data := w.Bytes()[auth.NonceSize() : w.Len()-auth.Overhead()]
		cryptext := w.Bytes()[auth.NonceSize():]

		auth.Seal(cryptext[:0], nonce, data, nil)
	}

	return nil
}

func DecodePacket(r []byte, auth Auth, prefix bool) ([]byte, netapi.Address, error) {
	if auth != nil {
		if auth.NonceSize() > 0 {
			if len(r) < auth.NonceSize() {
				return nil, nil, fmt.Errorf("nonce is not enough")
			}

			nonce := r[:auth.NonceSize()]
			cryptext := r[auth.NonceSize():]
			r = r[auth.NonceSize() : len(r)-auth.Overhead()]

			_, err := auth.Open(r[:0], nonce, cryptext, nil)
			if err != nil {
				return nil, nil, err
			}
		}

		if auth.KeySize() > 0 {
			if len(r) < auth.KeySize() {
				return nil, nil, fmt.Errorf("key is not enough")
			}

			rkey := r[:auth.KeySize()]
			r = r[auth.KeySize():]

			if subtle.ConstantTimeCompare(rkey, auth.Key()) == 0 {
				return nil, nil, fmt.Errorf("key is incorrect")
			}
		}
	}

	n := 3
	if !prefix {
		n = 0
	}

	if len(r) < n {
		return nil, nil, fmt.Errorf("packet is not enough")
	}

	addr, err := tools.ResolveAddr(bytes.NewReader(r[n:]))
	if err != nil {
		return nil, nil, err
	}

	return r[n+len(addr):], addr.Address(statistic.Type_udp), nil
}

func StartUDPServer(ctx context.Context, packet net.PacketConn, channel chan *netapi.Packet, auth Auth, prefix bool) {
	p := NewAuthPacketConn(packet, nil, nil, auth, prefix)
	for {
		buf := pool.GetBytesBuffer(nat.MaxSegmentSize)

		n, dst, src, err := p.readFrom(buf.Bytes())
		if err != nil {
			log.Error("read udp request failed", slog.Any("err", err))

			if errors.Is(err, ErrNet) {
				return
			}

			continue
		}

		buf.ResetSize(0, n)

		select {
		case <-ctx.Done():
			return
		case channel <- &netapi.Packet{
			Src:       src,
			Dst:       dst,
			Payload:   buf,
			WriteBack: func(b []byte, source net.Addr) (int, error) { return p.writeTo(b, source, src) },
		}:
		}
	}
}
