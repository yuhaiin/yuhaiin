package yuubinsya

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type authPacketConn struct {
	net.PacketConn
	realTarget net.Addr

	auth types.Auth

	onClose func() error
	prefix  bool
}

func NewAuthPacketConn(local net.PacketConn) *authPacketConn {
	return &authPacketConn{PacketConn: local}
}

func (s *authPacketConn) Close() error {
	var err error
	if s.onClose != nil {
		if er := s.onClose(); er != nil {
			err = errors.Join(err, er)
		}
	}
	if er := s.PacketConn.Close(); er != nil {
		err = errors.Join(err, er)
	}
	return err
}

func (s *authPacketConn) WithOnClose(close func() error) *authPacketConn {
	s.onClose = close
	return s
}

func (s *authPacketConn) WithRealTarget(target net.Addr) *authPacketConn {
	s.realTarget = target
	return s
}

func (s *authPacketConn) WithAuth(auth types.Auth) *authPacketConn {
	s.auth = auth

	return s
}

// Socks5 Prefix , append 0x0, 0x0, 0x0 to packet
func (s *authPacketConn) WithSocks5Prefix(b bool) *authPacketConn {
	s.prefix = b
	return s
}

func (s *authPacketConn) WriteTo(p []byte, addr net.Addr) (_ int, err error) {
	return s.writeTo(p, addr, s.realTarget)
}

func (s *authPacketConn) writeTo(p []byte, addr net.Addr, underlyingAddr net.Addr) (_ int, err error) {
	if len(p) > nat.MaxSegmentSize-types.AuthHeaderSize(s.auth, s.prefix) {
		return 0, fmt.Errorf("packet too large: %d > %d", len(p), nat.MaxSegmentSize)
	}

	if underlyingAddr == nil {
		underlyingAddr = addr
	}

	buf := pool.NewBufferSize(len(p) + types.AuthHeaderSize(s.auth, s.prefix))
	defer buf.Reset()

	err = types.EncodePacket(buf, addr, p, s.auth, s.prefix)
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

var errNet = errors.New("network error")

func (s *authPacketConn) readFrom(p []byte) (int, netapi.Address, net.Addr, error) {
	n, rawAddr, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w read from remote failed: %w", errNet, err)
	}
	buf, addr, err := types.DecodePacket(p[:n], s.auth, s.prefix)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("decode packet failed: %w", err)
	}

	return copy(p[0:], buf), addr, rawAddr, nil
}

func StartUDPServer(packet net.PacketConn, handle func(*netapi.Packet), auth types.Auth, prefix bool) {
	p := NewAuthPacketConn(packet).WithAuth(auth).WithSocks5Prefix(prefix)
	buf := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(buf)

	for {
		n, dst, src, err := p.readFrom(buf)
		if err != nil {
			log.Error("read udp request failed", slog.Any("err", err))

			if errors.Is(err, errNet) {
				return
			}

			continue
		}

		handle(&netapi.Packet{
			Src:     src,
			Dst:     dst,
			Payload: buf[:n],
			WriteBack: func(b []byte, source net.Addr) (int, error) {
				return p.writeTo(b, source, src)
			},
		})
	}
}
