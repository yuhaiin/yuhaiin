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

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
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
	buf := pool.NewBufferSize(2048)
	defer buf.Reset()

	_, _ = buf.Write(c.password)
	_, _ = buf.Write(crlf)
	_ = buf.WriteByte(byte(cmd))
	tools.EncodeAddr(addr, buf)
	_, _ = buf.Write(crlf)

	_, err = conn.Write(buf.Bytes())
	return
}

// modified from https://github.com/p4gefau1t/trojan-go/blob/master/tunnel/trojan/client.go
type Client struct {
	proxy netapi.Proxy
	netapi.EmptyDispatch
	password []byte
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(config *protocol.Protocol_Trojan) point.WrapProxy {
	return func(dialer netapi.Proxy) (netapi.Proxy, error) {
		return &Client{
			password: hexSha224([]byte(config.Trojan.Password)),
			proxy:    dialer,
		}, nil
	}
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

	return &PacketConn{BufioConn: pool.NewBufioConnSize(conn, pool.DefaultSize)}, nil
}

type PacketConn struct {
	pool.BufioConn
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	w := pool.NewBufferSize(min(len(payload), MaxPacketSize) + 1024)
	defer w.Reset()

	tools.EncodeAddr(taddr, w)

	payload = payload[:min(len(payload), MaxPacketSize)]

	_ = pool.BinaryWriteUint16(w, binary.BigEndian, uint16(len(payload)))

	_, _ = w.Write(crlf) // crlf
	_, _ = w.Write(payload)

	_, err = c.BufioConn.Write(w.Bytes())
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
