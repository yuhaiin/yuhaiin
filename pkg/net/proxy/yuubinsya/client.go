package yuubinsya

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func (c *Client) WriteHeader(conn net.Conn, cmd byte, addr proxy.Address) (err error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	buf.WriteByte(cmd)
	buf.WriteByte(byte(len(c.password)))
	buf.Write(c.password)
	if cmd == tcp {
		s5c.ParseAddrWriter(addr, buf)
	}
	_, err = conn.Write(buf.Bytes())
	return
}

// modified from https://github.com/p4gefau1t/trojan-go/blob/master/tunnel/trojan/client.go
type Client struct {
	proxy    proxy.Proxy
	password []byte
}

func New(config *protocol.Protocol_Yuubinsya) protocol.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		return &Client{
			password: []byte(config.Yuubinsya.Password),
			proxy:    dialer,
		}, nil
	}
}

func (c *Client) Conn(addr proxy.Address) (net.Conn, error) {
	conn, err := c.proxy.Conn(addr)
	if err != nil {
		return nil, err
	}

	if err = c.WriteHeader(conn, tcp, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write header failed: %w", err)
	}
	return conn, nil
}

func (c *Client) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	conn, err := c.proxy.Conn(addr)
	if err != nil {
		return nil, err
	}
	if err = c.WriteHeader(conn, udp, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write header failed: %w", err)
	}
	return &PacketConn{Conn: conn}, nil
}

type PacketConn struct {
	net.Conn

	remain int
	addr   proxy.Address
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	w := pool.GetBuffer()
	defer pool.PutBuffer(w)

	s5c.ParseAddrWriter(taddr, w)
	addrSize := w.Len()

	b := bytes.NewBuffer(payload)

	for b.Len() > 0 {
		data := b.Next(MaxPacketSize)

		w.Truncate(addrSize)

		binary.Write(w, binary.BigEndian, uint16(len(data)))

		w.Write(data)

		_, err = c.Conn.Write(w.Bytes())
		if err != nil {
			return len(payload) - b.Len() + len(data), fmt.Errorf("write to %v failed: %w", addr, err)
		}
	}

	return len(payload), nil
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	if c.remain > 0 {
		n, err := c.Conn.Read(payload)
		if err != nil {
			return 0, c.addr, err
		}

		c.remain -= n
		return n, c.addr, err
	}

	addr, err := s5c.ResolveAddr(c.Conn)
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

	plen := len(payload)
	if int(length) < plen {
		plen = int(length)
	} else {
		c.remain = int(length) - plen
	}

	n, err = io.ReadFull(c.Conn, payload[:plen])
	return n, c.addr, err
}
