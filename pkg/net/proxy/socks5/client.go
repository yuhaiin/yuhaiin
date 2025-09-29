package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"google.golang.org/protobuf/proto"
)

func Dial(host, port, user, password string) netapi.Proxy {
	addr, err := netapi.ParseAddress("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return netapi.NewErrProxy(err)
	}
	simple, err := fixed.NewClient(protocol.Fixed_builder{
		Host: proto.String(addr.Hostname()),
		Port: proto.Int32(int32(addr.Port())),
	}.Build(), nil)
	if err != nil {
		return netapi.NewErrProxy(err)
	}

	p, _ := NewClient(protocol.Socks5_builder{
		Hostname: proto.String(host),
		User:     proto.String(user),
		Password: proto.String(password),
	}.Build(), simple)
	return p
}

// https://tools.ietf.org/html/rfc1928
// Client socks5 Client
type Client struct {
	netapi.EmptyDispatch
	dialer   netapi.Proxy
	username string
	password string

	hostname     string
	overridePort uint16
}

func init() {
	register.RegisterPoint(NewClient)
}

// New returns a new Socks5 client
func NewClient(config *protocol.Socks5, dialer netapi.Proxy) (netapi.Proxy, error) {
	return &Client{
		dialer:       dialer,
		username:     config.GetUser(),
		password:     config.GetPassword(),
		hostname:     config.GetHostname(),
		overridePort: uint16(config.GetOverridePort()),
	}, nil
}

func (s *Client) handshake1(conn net.Conn) error {
	_, err := conn.Write([]byte{0x05, 0x02, tools.NoAuthenticationRequired, tools.UserAndPassword})
	if err != nil {
		return fmt.Errorf("write sock5 header failed: %w", err)
	}

	header := make([]byte, 2)
	_, err = io.ReadFull(conn, header)
	if err != nil {
		return fmt.Errorf("read header failed: %w", err)
	}

	if header[0] != 0x05 {
		return errors.New("unknown socks5 version")
	}

	switch header[1] {
	case tools.NoAuthenticationRequired:
		return nil

	case tools.UserAndPassword: // username and password
		req := pool.NewBufferSize(pool.DefaultSize)
		defer req.Reset()

		_ = req.WriteByte(0x01)
		_ = req.WriteByte(byte(len(s.username)))
		_, _ = req.WriteString(s.username)
		_ = req.WriteByte(byte(len(s.password)))
		_, _ = req.WriteString(s.password)

		_, err = conn.Write(req.Bytes())
		if err != nil {
			return fmt.Errorf("write auth data failed: %w", err)
		}

		_, err = io.ReadFull(conn, header)
		if err != nil {
			return fmt.Errorf("read auth data failed: %w", err)
		}

		if header[1] != 0x00 {
			return fmt.Errorf("username or password not correct, socks5 handshake failed: err_code: %d", header[1])
		}

		return nil

	default:
		return fmt.Errorf("unsupported Authentication methods: %d", header[1])
	}
}

func (s *Client) handshake2(conn net.Conn, cmd tools.CMD, address netapi.Address) (target netapi.Address, err error) {
	req := pool.GetBytes(tools.MaxAddrLength + 3)
	defer pool.PutBytes(req)

	req[0] = 0x05
	req[1] = byte(cmd)
	req[2] = 0x00
	addrLen := tools.EncodeAddr(address, req[3:])

	if _, err = conn.Write(req[:addrLen+3]); err != nil {
		return nil, err
	}

	header := make([]byte, 3)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != 0x05 || header[1] != tools.Succeeded {
		return nil, fmt.Errorf("socks5 second handshake failed: ver: %d, err_code: %d", header[0], header[1])
	}

	socksAddr, err := tools.ResolveAddr(conn)
	if err != nil {
		return nil, fmt.Errorf("resolve addr failed: %w", err)
	}
	defer pool.PutBytes(socksAddr)

	addr := socksAddr.Address("tcp")

	if !addr.IsFqdn() && addr.(netapi.IPAddress).AddrPort().Addr().IsUnspecified() {
		addr, err = netapi.ParseAddressPort("tcp", s.hostname, uint16(addr.Port()))
		if err != nil {
			return nil, fmt.Errorf("parse address failed: %w", err)
		}
	}

	if s.overridePort != 0 {
		addr, err = netapi.ParseAddressPort(addr.Network(), addr.Hostname(), s.overridePort)
		if err != nil {
			return nil, fmt.Errorf("parse override port address failed: %w", err)
		}
	}

	return addr, nil
}

func (s *Client) Conn(ctx context.Context, host netapi.Address) (net.Conn, error) {
	conn, err := s.dialer.Conn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	err = s.handshake1(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("first hand failed: %w", err)
	}

	_, err = s.handshake2(conn, tools.Connect, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("second hand failed: %w", err)
	}

	return conn, nil
}

func (s *Client) PacketConn(ctx context.Context, host netapi.Address) (net.PacketConn, error) {
	conn, err := s.dialer.Conn(ctx, host)
	if err != nil {
		return nil, netapi.NewDialError("udp", err, host)
	}

	err = s.handshake1(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("first hand failed: %w", err)
	}

	addr, err := s.handshake2(conn, tools.Udp, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("second hand failed: %w", err)
	}

	pc, err := s.dialer.PacketConn(ctx, addr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("listen udp failed: %w", err)
	}

	pc = yuubinsya.NewAuthPacketConn(pc).WithOnClose(conn.Close).WithRealTarget(addr).WithSocks5Prefix(true)

	go func() {
		_, _ = relay.Copy(io.Discard, conn)
		pc.Close()
	}()

	return pc, nil
}

func (s *Client) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	start := time.Now()

	conn, err := s.dialer.Conn(ctx, addr)
	if err != nil {
		return 0, netapi.NewDialError("udp", err, addr)
	}
	defer conn.Close()

	err = s.handshake1(conn)
	if err != nil {
		return 0, fmt.Errorf("first hand failed: %w", err)
	}

	_, err = s.handshake2(conn, tools.Ping, addr)
	if err != nil {
		return 0, fmt.Errorf("second hand failed: %w", err)
	}

	return uint64(time.Since(start)), nil
}

func (s *Client) Close() error {
	return s.dialer.Close()
}
