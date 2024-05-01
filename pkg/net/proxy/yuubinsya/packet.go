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
	tcp    net.Conn
	server net.Addr

	auth types.Auth

	prefix bool
}

func NewAuthPacketConn(local net.PacketConn) *authPacketConn {
	return &authPacketConn{PacketConn: local}
}

func (s *authPacketConn) Close() error {
	if s.tcp != nil {
		s.tcp.Close()
	}
	return s.PacketConn.Close()
}

func (s *authPacketConn) WithTcpConn(tcp net.Conn) *authPacketConn {
	s.tcp = tcp
	return s
}

func (s *authPacketConn) WithTarget(target net.Addr) *authPacketConn {
	s.server = target
	return s
}

func (s *authPacketConn) WithAuth(auth types.Auth) *authPacketConn {
	s.auth = auth

	return s
}

func (s *authPacketConn) WithPrefix(b bool) *authPacketConn {
	s.prefix = b
	return s
}

func (s *authPacketConn) WriteTo(p []byte, addr net.Addr) (_ int, err error) {
	return s.writeTo(p, addr, s.server)
}

func (s *authPacketConn) writeTo(p []byte, addr net.Addr, underlyingAddr net.Addr) (_ int, err error) {
	buf := pool.GetBytesWriter(nat.MaxSegmentSize)
	defer buf.Free()

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

func StartUDPServer(packet net.PacketConn, sendPacket func(*netapi.Packet) error, auth types.Auth, prefix bool) {
	p := NewAuthPacketConn(packet).WithAuth(auth).WithPrefix(prefix)
	for {
		buf := pool.GetBytesBuffer(nat.MaxSegmentSize)

		n, dst, src, err := p.readFrom(buf.Bytes())
		if err != nil {
			log.Error("read udp request failed", slog.Any("err", err))

			if errors.Is(err, errNet) {
				return
			}

			continue
		}

		buf.Refactor(0, n)

		err = sendPacket(&netapi.Packet{
			Src:     src,
			Dst:     dst,
			Payload: buf,
			WriteBack: func(b []byte, source net.Addr) (int, error) {
				return p.writeTo(b, source, src)
			},
		})

		if err != nil {
			log.Error("send udp response failed", slog.Any("err", err))
			break
		}
	}
}
