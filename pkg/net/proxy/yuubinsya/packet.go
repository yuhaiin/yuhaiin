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

type AuthPacketConn struct {
	net.PacketConn

	password []byte
	rawAddr  net.Addr
	onClose  func() error
	prefix   bool
}

func NewAuthPacketConn(local net.PacketConn) *AuthPacketConn {
	return &AuthPacketConn{PacketConn: local}
}

func (s *AuthPacketConn) Close() error {
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

func (s *AuthPacketConn) WithOnClose(close func() error) *AuthPacketConn {
	s.onClose = close
	return s
}

func (s *AuthPacketConn) WithRealTarget(target net.Addr) *AuthPacketConn {
	s.rawAddr = target
	return s
}

func (s *AuthPacketConn) WithPassword(password []byte) *AuthPacketConn {
	s.password = password
	return s
}

// Socks5 Prefix , append 0x0, 0x0, 0x0 to packet
func (s *AuthPacketConn) WithSocks5Prefix(b bool) *AuthPacketConn {
	s.prefix = b
	return s
}

func (s *AuthPacketConn) WriteTo(p []byte, addr net.Addr) (_ int, err error) {
	return s.write(p, packetAddr{addr, s.rawAddr})
}

type packetAddr struct {
	ProxyAddr net.Addr
	RawAddr   net.Addr
}

func (s *AuthPacketConn) write(p []byte, addr packetAddr) (_ int, err error) {
	if len(p) > nat.MaxSegmentSize-AuthHeaderSize(s.password, s.prefix) {
		return 0, fmt.Errorf("packet too large: %d > %d", len(p), nat.MaxSegmentSize)
	}

	if addr.RawAddr == nil {
		addr.RawAddr = addr.ProxyAddr
	}

	buf := pool.NewBufferSize(len(p) + AuthHeaderSize(s.password, s.prefix))
	defer buf.Reset()

	err = EncodePacket(buf, addr.ProxyAddr, p, s.password, s.prefix)
	if err != nil {
		return 0, fmt.Errorf("encode packet failed: %w", err)
	}

	_, err = s.PacketConn.WriteTo(buf.Bytes(), addr.RawAddr)
	if err != nil {
		return 0, fmt.Errorf("write to remote failed: %w", err)
	}

	return len(p), nil
}

func (s *AuthPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := s.read(p)
	return n, addr.ProxyAddr, err
}

var errNet = errors.New("network error")

func (s *AuthPacketConn) read(p []byte) (int, packetAddr, error) {
	n, rawAddr, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, packetAddr{}, fmt.Errorf("%w read from remote failed: %w", errNet, err)
	}

	buf, addr, err := DecodePacket(p[:n], s.password, s.prefix)
	if err != nil {
		return 0, packetAddr{}, fmt.Errorf("decode packet failed: %w", err)
	}

	return copy(p[0:], buf), packetAddr{addr, rawAddr}, nil
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
		n, addr, err := p.read(buf)
		if err != nil {
			if errors.Is(err, errNet) {
				return err
			}

			log.Warn("read udp request failed", slog.Any("err", err))
			continue
		}

		proxyAddr, err := netapi.ParseSysAddr(addr.ProxyAddr)
		if err != nil {
			log.Warn("parse proxy addr failed", "err", err)
			continue
		}

		s.Handler(netapi.NewPacket(addr.RawAddr, proxyAddr, pool.Clone(buf[:n]),
			netapi.WriteBackFunc(func(b []byte, source net.Addr) (int, error) {
				return p.write(b, packetAddr{source, addr.RawAddr})
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
	if prefix {
		return len(password) + 3
	} else {
		return len(password)
	}
}
