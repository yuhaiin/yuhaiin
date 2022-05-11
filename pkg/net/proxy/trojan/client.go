package trojan

import (
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

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
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

var (
	crlf = []byte{'\r', '\n'}
)

type OutboundConn struct {
	cmd               Command
	addr              proxy.Address
	password          []byte
	headerWrittenOnce sync.Once
	net.Conn
}

func (c *OutboundConn) WriteHeader() (err error) {
	c.headerWrittenOnce.Do(func() {
		buf := utils.GetBuffer()
		defer utils.PutBuffer(buf)

		buf.Write(c.password)
		buf.Write(crlf)
		buf.WriteByte(byte(c.cmd))

		s5c.ParseAddrWriter(c.addr, buf)

		buf.Write(crlf)
		_, err = c.Conn.Write(buf.Bytes())
	})
	return
}

func (c *OutboundConn) Write(p []byte) (int, error) {
	err := c.WriteHeader()
	if err != nil {
		return 0, fmt.Errorf("trojan failed to flush header with payload: %w", err)
	}
	return c.Conn.Write(p)
}

// modified from https://github.com/p4gefau1t/trojan-go/blob/master/tunnel/trojan/client.go
type Client struct {
	proxy    proxy.Proxy
	password []byte
}

func NewClient(config *node.PointProtocol_Trojan) node.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		return &Client{
			password: hexSha224([]byte(config.Trojan.Password)),
			proxy:    dialer,
		}, nil
	}
}

func (c *Client) Conn(addr proxy.Address) (net.Conn, error) {
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
		newConn.WriteHeader()
	}(newConn)
	return newConn, nil
}

func (c *Client) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	conn, err := c.proxy.Conn(addr)
	if err != nil {
		return nil, err
	}
	return &PacketConn{
		Conn: &OutboundConn{
			Conn:     conn,
			cmd:      Associate,
			addr:     addr,
			password: c.password,
		},
	}, nil
}

type PacketConn struct {
	net.Conn
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	w := utils.GetBuffer()
	defer utils.PutBuffer(w)

	taddr, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	s5c.ParseAddrWriter(taddr, w)

	length := len(payload)
	lengthBuf := [2]byte{}
	binary.BigEndian.PutUint16(lengthBuf[:], uint16(length))
	w.Write(lengthBuf[:])

	w.Write(crlf) // crlf

	w.Write(payload)

	_, err = c.Conn.Write(w.Bytes())

	return length, err
}

func (c *PacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	host, port, _, err := s5c.ResolveAddrReader(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}

	lengthBuf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, lengthBuf[:]); err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))

	crlf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, crlf[:]); err != nil {
		return 0, nil, fmt.Errorf("read crlf failed: %w", err)
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
