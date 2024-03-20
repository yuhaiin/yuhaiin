package trojan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
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
	buf := pool.GetBytesWriter(pool.DefaultSize)
	defer buf.Free()

	_, _ = buf.Write(c.password)
	_, _ = buf.Write(crlf)
	buf.WriteByte(byte(cmd))
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
	return &PacketConn{Conn: conn}, nil
}

type PacketConn struct {
	net.Conn

	remain int
	addr   netapi.Address
	mux    sync.Mutex
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	w := pool.GetBuffer()
	defer pool.PutBuffer(w)

	tools.EncodeAddr(taddr, w)
	addrSize := w.Len()

	b := bytes.NewBuffer(payload)

	for b.Len() > 0 {
		data := b.Next(MaxPacketSize)

		w.Truncate(addrSize)

		binary.Write(w, binary.BigEndian, uint16(len(data)))

		w.Write(crlf) // crlf

		w.Write(data)

		_, err = c.Conn.Write(w.Bytes())
		if err != nil {
			return len(payload) - b.Len() + len(data), fmt.Errorf("write to %v failed: %w", addr, err)
		}
	}

	return len(payload), nil
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.remain > 0 {
		z := min(len(payload), c.remain)

		n, err := c.Conn.Read(payload[:z])
		if err != nil {
			return 0, c.addr, err
		}

		c.remain -= n
		return n, c.addr, err
	}

	addr, err := tools.ResolveAddr(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}

	c.addr = addr.Address(statistic.Type_udp)

	var length uint16
	if err = binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}
	if length > MaxPacketSize {
		return 0, nil, fmt.Errorf("invalid packet size")
	}

	crlf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, crlf[:]); err != nil {
		return 0, nil, fmt.Errorf("read crlf failed: %w", err)
	}

	plen := min(int(length), len(payload))
	c.remain = int(length) - plen

	n, err = io.ReadFull(c.Conn, payload[:plen])
	return n, c.addr, err
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
