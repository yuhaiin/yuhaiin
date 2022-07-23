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

type creator func(ProtocolInfo) IProtocol

var (
	creatorMap = make(map[string]creator)
)

type hmacMethod func(key []byte, data []byte, buf []byte) []byte
type hashDigestMethod func(data []byte) []byte
type rndMethod func(dataLength int, random *ssr.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int

type IProtocol interface {
	EncryptStream(dst *bytes.Buffer, data []byte) error
	DecryptStream(dst *bytes.Buffer, data []byte) (int, error)
	EncryptPacket(data []byte) ([]byte, error)
	DecryptPacket(data []byte) ([]byte, error)

	GetOverhead() int
}

type AuthData struct {
	clientID     []byte
	connectionID uint32

	lock sync.Mutex
}

func (a *AuthData) nextAuth() {
	if a.connectionID <= 0xFF000000 && len(a.clientID) != 0 {
		atomic.AddUint32(&a.connectionID, 1)
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()
	a.clientID = make([]byte, 8)
	rand.Read(a.clientID)
	atomic.StoreUint32(&a.connectionID, rand.Uint32()&0xFFFFFF)
}

func register(name string, c creator) {
	creatorMap[name] = c
}

func createProtocol(name string, info ProtocolInfo) IProtocol {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c(info)
	}
	return nil
}

func checkProtocol(name string) error {
	if _, ok := creatorMap[strings.ToLower(name)]; !ok {
		return fmt.Errorf("protocol %s not found", name)
	}
	return nil
}

type Protocol struct {
	name string
	info ProtocolInfo
}

func NewProtocol(name string, info ProtocolInfo) (*Protocol, error) {
	if err := checkProtocol(name); err != nil {
		return nil, err
	}
	return &Protocol{name, info}, nil
}

func (p *Protocol) Stream(conn net.Conn, writeIV []byte) net.Conn {
	i := p.info
	i.IV = writeIV
	return newProtocolConn(conn, createProtocol(p.name, i))
}

func (p *Protocol) Packet(conn net.PacketConn) *protocolPacket {
	return newProtocolPacket(conn, createProtocol(p.name, p.info))
}

type protocolPacket struct {
	protocol IProtocol
	net.PacketConn
}

func newProtocolPacket(conn net.PacketConn, p IProtocol) *protocolPacket {
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
	protocol IProtocol
	net.Conn

	readBuf             [utils.DefaultSize / 4]byte
	underPostdecryptBuf bytes.Buffer
	decryptedBuf        bytes.Buffer
}

func newProtocolConn(c net.Conn, p IProtocol) *protocolConn {
	return &protocolConn{
		Conn:     c,
		protocol: p,
	}
}

func (c *protocolConn) Read(b []byte) (n int, err error) {
	if c.decryptedBuf.Len() > 0 {
		return c.decryptedBuf.Read(b)
	}

	n, err = c.Conn.Read(c.readBuf[:])
	if err != nil {
		return 0, err
	}

	c.underPostdecryptBuf.Write(c.readBuf[:n])
	length, err := c.protocol.DecryptStream(&c.decryptedBuf, c.underPostdecryptBuf.Bytes())
	if err != nil {
		c.underPostdecryptBuf.Reset()
		return 0, err
	}
	c.underPostdecryptBuf.Next(length)

	n, _ = c.decryptedBuf.Read(b)
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

type ProtocolInfo struct {
	ssr.Info
	HeadSize int
	TcpMss   int
	Param    string
	IV       []byte

	Auth *AuthData

	ObfsOverhead int
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
