package yuubinsya

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type authPacketConn struct {
	net.PacketConn
	password   []byte
	realTarget net.Addr

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

func (s *authPacketConn) WithPassword(password []byte) *authPacketConn {
	s.password = password
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
	if len(p) > nat.MaxSegmentSize-AuthHeaderSize(s.password, s.prefix) {
		return 0, fmt.Errorf("packet too large: %d > %d", len(p), nat.MaxSegmentSize)
	}

	if underlyingAddr == nil {
		underlyingAddr = addr
	}

	buf := pool.NewBufferSize(len(p) + AuthHeaderSize(s.password, s.prefix))
	defer buf.Reset()

	err = EncodePacket(buf, addr, p, s.password, s.prefix)
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

	buf, addr, err := DecodePacket(p[:n], s.password, s.prefix)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("decode packet failed: %w", err)
	}

	return copy(p[0:], buf), addr, rawAddr, nil
}

type UDPServer struct {
	PacketConn net.PacketConn
	Handler    func(*netapi.Packet)
	Prefix     bool
	Password   []byte
}

func (s *UDPServer) Serve() error {
	p := NewAuthPacketConn(s.PacketConn).WithSocks5Prefix(s.Prefix).WithPassword(s.Password)

	buf := pool.GetBytes(configuration.UDPBufferSize.Load() + MaxPacketHeaderSize(s.Password, s.Prefix))
	defer pool.PutBytes(buf)

	for {
		n, dst, src, err := p.readFrom(buf)
		if err != nil {
			if errors.Is(err, errNet) {
				return err
			}

			log.Warn("read udp request failed", slog.Any("err", err))
			continue
		}

		s.Handler(netapi.NewPacket(src, dst, pool.Clone(buf[:n]),
			netapi.WriteBackFunc(func(b []byte, source net.Addr) (int, error) {
				return p.writeTo(b, source, src)
			})))
	}
}

func EncodePacket(w *pool.Buffer, addr net.Addr, buf []byte, password []byte, prefix bool) error {
	ad, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return fmt.Errorf("parse addr failed: %w", err)
	}

	if len(password) > 0 {
		_, _ = w.Write(password)
	}

	if prefix {
		_, _ = w.Write([]byte{0, 0, 0})
	}

	tools.WriteAddr(ad, w)

	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	return nil
}

func MaxPacketHeaderSize(password []byte, prefix bool) int {
	return tools.MaxAddrLength + AuthHeaderSize(password, prefix)
}

func DecodePacket(r []byte, password []byte, prefix bool) ([]byte, netapi.Address, error) {
	if len(password) > 0 {
		if len(r) < len(password) {
			return nil, nil, fmt.Errorf("key is not enough")
		}

		rkey := r[:len(password)]
		r = r[len(password):]

		if subtle.ConstantTimeCompare(rkey, password) != 1 {
			return nil, nil, fmt.Errorf("key is incorrect")
		}
	}

	if prefix {
		if len(r) < 3 {
			return nil, nil, fmt.Errorf("packet is not enough")
		}

		r = r[3:]
	}

	an, addr, err := tools.DecodeAddr("udp", r)
	if err != nil {
		return nil, nil, err
	}

	return r[an:], addr, nil
}

func AuthHeaderSize(password []byte, prefix bool) int {
	var a int

	if len(password) > 0 {
		a = len(password)
	}

	if prefix {
		a += 3
	}

	return a
}
