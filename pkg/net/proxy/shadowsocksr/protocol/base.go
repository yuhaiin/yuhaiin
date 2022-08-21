package protocol

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

type Protocol interface {
	EncryptStream(dst *bytes.Buffer, data []byte) error
	DecryptStream(dst *bytes.Buffer, data []byte) (int, error)
	EncryptPacket(data []byte) ([]byte, error)
	DecryptPacket(data []byte) ([]byte, error)

	GetOverhead() int
}

type errorProtocol struct{ error }

func NewErrorProtocol(err error) Protocol                                   { return &errorProtocol{err} }
func (e *errorProtocol) EncryptStream(dst *bytes.Buffer, data []byte) error { return e.error }
func (e *errorProtocol) DecryptStream(dst *bytes.Buffer, data []byte) (int, error) {
	return 0, e.error
}
func (e *errorProtocol) EncryptPacket(data []byte) ([]byte, error) { return nil, e.error }
func (e *errorProtocol) DecryptPacket(data []byte) ([]byte, error) { return nil, e.error }
func (e *errorProtocol) GetOverhead() int                          { return 0 }

type AuthData struct {
	clientID     []byte
	connectionID atomic.Uint32

	lock sync.Mutex
}

func (a *AuthData) nextAuth() {
	if a.connectionID.Load() <= 0xFF000000 && len(a.clientID) != 0 {
		a.connectionID.Add(1)
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()
	a.clientID = make([]byte, 8)
	rand.Read(a.clientID)
	a.connectionID.Store(rand.Uint32() & 0xFFFFFF)
}

type protocolPacket struct {
	protocol Protocol
	net.PacketConn
}

func newPacketConn(conn net.PacketConn, p Protocol) net.PacketConn {
	return &protocolPacket{PacketConn: conn, protocol: p}
}

func (c *protocolPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	data, err := c.protocol.EncryptPacket(b)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(data, addr)
	return len(b), err
}

func (c *protocolPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	decoded, err := c.protocol.DecryptPacket(b[:n])
	if err != nil {
		return n, addr, err
	}
	copy(b, decoded)
	return len(decoded), addr, nil
}

func (c *protocolPacket) Close() error { return c.PacketConn.Close() }

type protocolConn struct {
	protocol Protocol
	net.Conn

	readBuf               [utils.DefaultSize / 4]byte
	ciphertext, plaintext bytes.Buffer
}

func newConn(c net.Conn, p Protocol) net.Conn {
	return &protocolConn{
		Conn:     c,
		protocol: p,
	}
}

func (c *protocolConn) Read(b []byte) (n int, err error) {
	if c.plaintext.Len() > 0 {
		return c.plaintext.Read(b)
	}

	n, err = c.Conn.Read(c.readBuf[:])
	if err != nil {
		return 0, err
	}

	c.ciphertext.Write(c.readBuf[:n])
	length, err := c.protocol.DecryptStream(&c.plaintext, c.ciphertext.Bytes())
	if err != nil {
		c.ciphertext.Reset()
		return 0, err
	}
	c.ciphertext.Next(length)

	n, _ = c.plaintext.Read(b)
	return n, nil
}

func (c *protocolConn) Write(b []byte) (n int, err error) {
	buf := utils.GetBuffer()
	defer utils.PutBuffer(buf)

	if err = c.protocol.EncryptStream(buf, b); err != nil {
		return 0, err
	}
	if _, err = c.Conn.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(b), nil
}

var ProtocolMap = map[string]func(ProtocolInfo) Protocol{
	"auth_aes128_sha1": NewAuthAES128SHA1,
	"auth_aes128_md5":  NewAuthAES128MD5,
	"auth_chain_a":     NewAuthChainA,
	"auth_chain_b":     NewAuthChainB,
	"origin":           NewOrigin,
	"auth_sha1_v4":     NewAuthSHA1v4,
	"verify_sha1":      NewVerifySHA1,
	"ota":              NewVerifySHA1,
}

type ProtocolInfo struct {
	ssr.Info

	Name     string
	HeadSize int
	TcpMss   int
	Param    string
	IV       []byte

	Auth *AuthData

	ObfsOverhead int
}

func (s ProtocolInfo) stream() (Protocol, error) {
	c, ok := ProtocolMap[strings.ToLower(s.Name)]
	if ok {
		return c(s), nil
	}
	return nil, fmt.Errorf("protocol %s not found", s.Name)
}

func (s ProtocolInfo) Stream(c net.Conn, iv []byte) (net.Conn, error) {
	z := s
	z.IV = iv

	p, err := z.stream()
	if err != nil {
		return nil, err
	}
	return newConn(c, p), nil
}

func (s ProtocolInfo) Packet(c net.PacketConn) (net.PacketConn, error) {
	p, err := s.stream()
	if err != nil {
		return nil, err
	}
	return newPacketConn(c, p), nil
}

func (s *ProtocolInfo) SetHeadLen(data []byte, defaultValue int) {
	s.HeadSize = GetHeadSize(data, defaultValue)
}

// https://github.com/shadowsocksrr/shadowsocksr/blob/fd723a92c488d202b407323f0512987346944136/shadowsocks/obfsplugin/plain.py#L93
func GetHeadSize(data []byte, defaultValue int) int {
	if len(data) < 2 {
		return defaultValue
	}
	headType := data[0] & 0x07
	switch headType {
	case 1:
		// IPv4 1+4+2
		return 7
	case 4:
		// IPv6 1+16+2
		return 19
	case 3:
		// domain name, variant length
		return 4 + int(data[1])
	}

	return defaultValue
}
