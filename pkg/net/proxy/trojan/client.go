package trojan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

const (
	MaxPacketSize = 1024 * 8
)

type Command byte

const (
	Connect   Command = 1 // TCP
	Associate Command = 3 // UDP
	Mux       Command = 0x7f
)

var crlf = []byte{'\r', '\n'}

func (c *Client) WriteHeader(conn net.Conn, cmd Command, addr netapi.Address) (err error) {
	buf := pool.GetBytes(tools.MaxAddrLength + len(c.password) + len(crlf)*2 + 1)
	defer pool.PutBytes(buf)

	n := copy(buf, c.password)
	n += copy(buf[n:], crlf)
	n += copy(buf[n:], []byte{byte(cmd)})
	n += tools.EncodeAddr(addr, buf[n:])
	n += copy(buf[n:], crlf)

	_, err = conn.Write(buf[:n])
	return
}

// modified from https://github.com/p4gefau1t/trojan-go/blob/master/tunnel/trojan/client.go
type Client struct {
	proxy netapi.Proxy
	netapi.EmptyDispatch
	password []byte
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *protocol.Trojan, dialer netapi.Proxy) (netapi.Proxy, error) {
	return &Client{
		password: hexSha224([]byte(config.GetPassword())),
		proxy:    dialer,
	}, nil
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := c.proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	if err = c.WriteHeader(conn, Connect, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write header failed: %w", err)
	}
	return conn, nil
}

func (c *Client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	conn, err := c.proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}
	if err = c.WriteHeader(conn, Associate, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write header failed: %w", err)
	}

	return &PacketConn{BufioConn: pool.NewBufioConnSize(conn, configuration.UDPBufferSize.Load())}, nil
}

type PacketConn struct {
	pool.BufioConn
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	payloadLen := len(payload)

	if payloadLen > MaxPacketSize {
		return 0, fmt.Errorf("payload too large: %d > %d", payloadLen, MaxPacketSize)
	}

	buf := pool.GetBytes(payloadLen + tools.MaxAddrLength + 2 + len(crlf))
	defer pool.PutBytes(buf)

	n := tools.EncodeAddr(taddr, buf)
	binary.BigEndian.PutUint16(buf[n:], uint16(payloadLen))
	n += 2
	n += copy(buf[n:], crlf)
	n += copy(buf[n:], payload)

	_, err = c.BufioConn.Write(buf[:n])
	if err != nil {
		return 0, err
	}

	return len(payload), nil
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, addr net.Addr, err error) {
	err = c.BufioConn.BufioRead(func(r *bufio.Reader) error {
		_, addr, err = tools.ReadAddr("udp", r)
		if err != nil {
			return fmt.Errorf("failed to resolve udp packet addr: %w", err)
		}

		// length + crlf
		buf, err := r.Peek(4)
		if err != nil {
			return fmt.Errorf("failed to read length: %w", err)
		}

		length := binary.BigEndian.Uint16(buf[:2])

		n, err = io.ReadFull(r, payload[:min(int(length), len(payload))])

		if length > uint16(n) {
			_, _ = relay.CopyN(io.Discard, r, int64(int(length)-n))
		}

		return err
	})

	return n, addr, err
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
