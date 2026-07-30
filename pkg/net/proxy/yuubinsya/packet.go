package yuubinsya

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type AuthPacketConn struct {
	net.PacketConn

	rawAddr net.Addr
	onClose func() error

	password  []byte
	passwords [][]byte
	auth      func([]byte) bool
	prefix    bool
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

func (s *AuthPacketConn) WithPasswords(passwords [][]byte) *AuthPacketConn {
	s.passwords = passwords
	if len(passwords) > 0 {
		s.password = passwords[0]
	}
	return s
}

func (s *AuthPacketConn) WithAuthenticator(auth func([]byte) bool) *AuthPacketConn {
	s.auth = auth
	if auth != nil {
		s.password = make([]byte, 32)
	}
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
	if len(p) > nat.MaxSegmentSize-MaxPacketHeaderSize(s.password, s.prefix) {
		return 0, fmt.Errorf("packet too large: %d > %d", len(p), nat.MaxSegmentSize)
	}

	if addr.RawAddr == nil {
		addr.RawAddr = addr.ProxyAddr
	}

	buf := pool.GetBytes(len(p) + MaxPacketHeaderSize(s.password, s.prefix))
	defer pool.PutBytes(buf)

	data, err := EncodePacket(buf,
		addr.ProxyAddr, p, s.password, s.prefix)
	if err != nil {
		return 0, fmt.Errorf("encode packet failed: %w", err)
	}

	_, err = s.PacketConn.WriteTo(data, addr.RawAddr)
	if err != nil {
		return 0, fmt.Errorf("write to remote failed: %w", err)
	}

	return len(p), nil
}

func (s *AuthPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := s.read(p)
	return n, addr.ProxyAddr, err
}

func (s *AuthPacketConn) read(p []byte) (int, packetAddr, error) {
	n, rawAddr, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, packetAddr{}, fmt.Errorf("read from packetConn failed: %w", err)
	}

	var buf []byte
	var addr netapi.Address
	var matched []byte
	if s.auth != nil {
		if n < 32 || !s.auth(p[:32]) {
			return 0, packetAddr{}, errors.New("decode packet failed: key is incorrect")
		}
		buf, addr, err = DecodePacket(p[:n], p[:32], s.prefix)
		if err != nil {
			return 0, packetAddr{}, fmt.Errorf("decode packet failed: %w", err)
		}
		s.password = append(s.password[:0], p[:32]...)
	} else if len(s.passwords) > 0 {
		for _, password := range s.passwords {
			decoded, decodedAddr, decodeErr := DecodePacket(p[:n], password, s.prefix)
			if decodeErr == nil {
				buf, addr, matched = decoded, decodedAddr, password
				break
			}
		}
		if matched == nil {
			return 0, packetAddr{}, errors.New("decode packet failed: key is incorrect")
		}
	} else {
		buf, addr, err = DecodePacket(p[:n], s.password, s.prefix)
		if err != nil {
			return 0, packetAddr{}, fmt.Errorf("decode packet failed: %w", err)
		}
	}
	if matched != nil {
		s.password = matched
	}

	return copy(p[0:], buf), packetAddr{addr, rawAddr}, nil
}

type UDPServer struct {
	PacketConn net.PacketConn
	Handler    func(*netapi.Packet)
	Password   []byte
	Passwords  [][]byte
	Auth       func([]byte) bool
	Prefix     bool
}

func (s *UDPServer) Serve() error {
	p := NewAuthPacketConn(s.PacketConn).WithSocks5Prefix(s.Prefix)
	if len(s.Passwords) > 0 {
		p.WithPasswords(s.Passwords)
	} else if s.Auth != nil {
		p.WithAuthenticator(s.Auth)
	} else {
		p.WithPassword(s.Password)
	}

	password := s.Password
	if s.Auth != nil {
		password = make([]byte, 32)
	}
	buf := pool.GetBytes(configuration.UDPBufferSize.Load() + MaxPacketHeaderSize(password, s.Prefix))
	defer pool.PutBytes(buf)

	for {
		n, addr, err := p.read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.ErrClosedPipe) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, context.Canceled) {
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

func EncodePacket(dst []byte, addr net.Addr, data, password []byte, prefix bool) ([]byte, error) {
	ad, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	n := copy(dst, password)
	if prefix {
		n += copy(dst[n:], []byte{0, 0, 0})
	}
	n += tools.EncodeAddr(ad, dst[n:])
	n += copy(dst[n:], data)
	return dst[:n], nil
}

func MaxPacketHeaderSize(password []byte, prefix bool) int {
	if prefix {
		return len(password) + 3 + tools.MaxAddrLength
	} else {
		return len(password) + tools.MaxAddrLength
	}
}

func DecodePacket(r []byte, password []byte, prefix bool) ([]byte, netapi.Address, error) {
	if len(r) < MaxPacketHeaderSize(password, prefix)-tools.MaxAddrLength {
		return nil, nil, fmt.Errorf("packet is not enough")
	}

	if len(password) > 0 && subtle.ConstantTimeCompare(r[:len(password)], password) != 1 {
		return nil, nil, fmt.Errorf("key is incorrect")
	}

	r = r[len(password):]

	if prefix {
		r = r[3:]
	}

	an, addr, err := tools.DecodeAddr("udp", r)
	if err != nil {
		return nil, nil, err
	}

	return r[an:], addr, nil
}
