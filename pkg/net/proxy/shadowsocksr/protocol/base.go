package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

type hmacMethod func(key []byte, data []byte) []byte
type hashDigestMethod func(data []byte) []byte
type rndMethod func(dataLength int, random *ssr.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int

type IProtocol interface {
	EncryptStream(data []byte) ([]byte, error)
	DecryptStream(data []byte) ([]byte, int, error)
	EncryptPacket(data []byte) ([]byte, error)
	DecryptPacket(data []byte) ([]byte, error)
	io.Closer

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
	return &protocolPacket{
		PacketConn: conn,
		protocol:   p,
	}
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

func (c *protocolPacket) Close() error {
	c.protocol.Close()

	return c.PacketConn.Close()
}

type protocolConn struct {
	protocol IProtocol
	net.Conn
	readBuf             []byte
	underPostdecryptBuf *bytes.Buffer
	decryptedBuf        *bytes.Buffer
}

func newProtocolConn(c net.Conn, p IProtocol) *protocolConn {
	return &protocolConn{
		Conn:                c,
		protocol:            p,
		readBuf:             utils.GetBytes(2048),
		decryptedBuf:        getBuffer(),
		underPostdecryptBuf: getBuffer(),
	}
}

func (c *protocolConn) Close() error {
	utils.PutBytes(c.readBuf)
	putBuffer(c.decryptedBuf)
	putBuffer(c.underPostdecryptBuf)
	c.protocol.Close()
	return c.Conn.Close()
}

func (c *protocolConn) Read(b []byte) (n int, err error) {
	for {
		n, err = c.doRead(b)
		if b == nil || n != 0 || err != nil {
			return n, err
		}
	}
}

func (c *protocolConn) doRead(b []byte) (n int, err error) {
	if c.decryptedBuf.Len() > 0 {
		return c.decryptedBuf.Read(b)
	}

	n, err = c.Conn.Read(c.readBuf)
	if n == 0 || err != nil {
		return n, err
	}

	c.underPostdecryptBuf.Write(c.readBuf[:n])

	decryptedData, length, err := c.protocol.DecryptStream(c.underPostdecryptBuf.Bytes())
	if err != nil {
		c.underPostdecryptBuf.Reset()
		return 0, err
	}

	if length == 0 {
		// not enough to decrypt
		return 0, nil
	}

	c.underPostdecryptBuf.Next(length)

	postDecryptedLength, blength := len(decryptedData), len(b)

	if blength >= postDecryptedLength {
		blength = postDecryptedLength
	}

	copy(b, decryptedData[:blength])
	c.decryptedBuf.Write(decryptedData[blength:])

	return blength, nil
}

func (c *protocolConn) Write(b []byte) (n int, err error) {
	data, err := c.protocol.EncryptStream(b)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

var bufpool = sync.Pool{
	New: func() any { return bytes.NewBuffer(nil) },
}

func getBuffer() *bytes.Buffer {
	return bufpool.Get().(*bytes.Buffer)
}

func putBuffer(b *bytes.Buffer) {
	b.Reset()
	bufpool.Put(b)
}

func (c *protocolConn) ReadFrom(r io.Reader) (int64, error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)

	n := int64(0)
	for {
		nr, er := r.Read(buf)
		n += int64(nr)
		_, err := c.Write(buf[:nr])
		if err != nil {
			return n, err
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return n, nil
			}
			return n, er
		}
	}
}

func (c *protocolConn) WriteTo(w io.Writer) (int64, error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)

	n := int64(0)
	for {
		nr, er := c.Read(buf)
		if nr > 0 {
			nw, err := w.Write(buf[:nr])
			n += int64(nw)
			if err != nil {
				return n, err
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return n, nil
			}
			return n, er
		}
	}
}

type ProtocolInfo struct {
	ssr.Info
	HeadLen int
	TcpMss  int
	Param   string
	IV      []byte

	Auth *AuthData

	ObfsOverhead int
}

func (s *ProtocolInfo) SetHeadLen(data []byte, defaultValue int) {
	s.HeadLen = GetHeadSize(data, defaultValue)
}

func GetHeadSize(data []byte, defaultValue int) int {
	if data == nil || len(data) < 2 {
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
