package trojan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	socks5client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

const (
	MaxPacketSize = 1024 * 8
)

type Command byte

const (
	Connect   Command = 1
	Associate Command = 3
	Mux       Command = 0x7f
)

type OutboundConn struct {
	cmd               Command
	addr              string
	password          []byte
	headerWrittenOnce sync.Once
	net.Conn
}

func (c *OutboundConn) WriteHeader(payload []byte) (bool, error) {
	var err error
	written := false
	c.headerWrittenOnce.Do(func() {
		buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
		crlf := []byte{0x0d, 0x0a}
		buf.Write(c.password)
		buf.Write(crlf)
		buf.WriteByte(byte(c.cmd))

		var d []byte
		d, err = socks5client.ParseAddr(c.addr)
		if err != nil {
			return
		}
		buf.Write(d)

		buf.Write(crlf)
		if payload != nil {
			buf.Write(payload)
		}
		_, err = c.Conn.Write(buf.Bytes())
		if err == nil {
			written = true
		}
	})
	return written, err
}

func (c *OutboundConn) Write(p []byte) (int, error) {
	written, err := c.WriteHeader(p)
	if err != nil {
		return 0, fmt.Errorf("trojan failed to flush header with payload: %w", err)
	}
	if written {
		return len(p), nil
	}
	n, err := c.Conn.Write(p)
	return n, err
}

func (c *OutboundConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	return n, err
}

func (c *OutboundConn) Close() error {
	return c.Conn.Close()
}

// modified from https://github.com/p4gefau1t/trojan-go/blob/master/tunnel/trojan/client.go
type Client struct {
	proxy    proxy.Proxy
	password []byte
}

func NewClient(password string) func(proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		return &Client{
			password: hexSha224([]byte(password)),
			proxy:    p,
		}, nil
	}
}

func (c *Client) Conn(addr string) (net.Conn, error) {
	conn, err := c.proxy.Conn(addr)
	if err != nil {
		return nil, err
	}

	newConn := &OutboundConn{
		Conn:     conn,
		password: c.password,
		cmd:      Connect,
		addr:     addr,
	}

	go func(newConn *OutboundConn) {
		// if the trojan header is still buffered after 100 ms, the client may expect data from the server
		// so we flush the trojan header
		time.Sleep(time.Millisecond * 100)
		newConn.WriteHeader(nil)
	}(newConn)
	return newConn, nil
}

func (c *Client) PacketConn(addr string) (net.PacketConn, error) {
	conn, err := c.proxy.Conn(addr)
	if err != nil {
		return nil, err
	}
	return &PacketConn{
		Conn: &OutboundConn{
			Conn: conn,
			cmd:  Associate,
			addr: addr,
		},
	}, nil
}

type PacketConn struct {
	net.Conn
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	packet := make([]byte, 0, MaxPacketSize)
	w := bytes.NewBuffer(packet)
	d, err := socks5client.ParseAddr(addr.String())
	if err != nil {
		return 0, fmt.Errorf("failed to parse address: %w", err)
	}
	w.Write(d)
	length := len(payload)
	lengthBuf := [2]byte{}
	crlf := [2]byte{0x0d, 0x0a}

	binary.BigEndian.PutUint16(lengthBuf[:], uint16(length))
	w.Write(lengthBuf[:])
	w.Write(crlf[:])
	w.Write(payload)

	_, err = c.Conn.Write(w.Bytes())

	return len(payload), err
}

func (c *PacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	host, port, _, err := socks5client.ResolveAddrReader(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}
	lengthBuf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, lengthBuf[:]); err != nil {
		return 0, nil, fmt.Errorf("failed to read length")
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))

	crlf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, crlf[:]); err != nil {
		return 0, nil, fmt.Errorf("failed to read crlf")
	}

	if len(payload) < length || length > MaxPacketSize {
		io.CopyN(ioutil.Discard, c.Conn, int64(length)) // drain the rest of the packet
		return 0, nil, fmt.Errorf("incoming packet size is too large")
	}

	if _, err := io.ReadFull(c.Conn, payload[:length]); err != nil {
		return 0, nil, fmt.Errorf("failed to read payload")
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	return length, addr, err
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
