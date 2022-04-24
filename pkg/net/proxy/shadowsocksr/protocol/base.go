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

type creator func(ssr.ServerInfo) IProtocol

var (
	creatorMap = make(map[string]creator)
)

type hmacMethod func(key []byte, data []byte) []byte
type hashDigestMethod func(data []byte) []byte
type rndMethod func(dataLength int, random *ssr.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int

type IProtocol interface {
	PreEncrypt(data []byte) ([]byte, error)
	PostDecrypt(data []byte) ([]byte, int, error)
	PreEncryptPacket(data []byte) ([]byte, error)
	PostDecryptPacket(data []byte) ([]byte, error)
	GetOverhead() int
	AddOverhead(size int)

	GetData() interface{}
	SetData(interface{})
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

func createProtocol(name string, info ssr.ServerInfo) IProtocol {
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
	name     string
	info     ssr.ServerInfo
	auth     *AuthData
	overhead int
}

func NewProtocol(name string, info ssr.ServerInfo, overhead int) (*Protocol, error) {
	if err := checkProtocol(name); err != nil {
		return nil, err
	}
	return &Protocol{name, info, &AuthData{}, overhead}, nil
}

func (p *Protocol) StreamProtocol(conn net.Conn, writeIV []byte) net.Conn {
	i := p.info
	i.IV = writeIV
	pt := createProtocol(p.name, i)
	pt.SetData(p.auth)
	pt.AddOverhead(p.overhead)
	return newProtocolConn(conn, pt)
}

func (p *Protocol) PacketProtocol(conn net.PacketConn) *protocolPacket {
	i := p.info
	pt := createProtocol(p.name, i)
	pt.SetData(p.auth)
	pt.AddOverhead(p.overhead)
	return newProtocolPacket(conn, pt)
}

type protocolPacket struct {
	IProtocol
	net.PacketConn
}

func newProtocolPacket(conn net.PacketConn, p IProtocol) *protocolPacket {
	return &protocolPacket{
		PacketConn: conn,
		IProtocol:  p,
	}
}

func (c *protocolPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	data, err := c.IProtocol.PreEncryptPacket(b)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(data, addr)
	// defer log.Println("write to", addr, "error", err)
	return len(b), err
}

func (c *protocolPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	decoded, err := c.IProtocol.PostDecryptPacket(b[:n])
	if err != nil {
		return n, addr, err
	}
	copy(b, decoded)
	return len(decoded), addr, nil
}

type protocolConn struct {
	IProtocol
	net.Conn
	readBuf             []byte
	underPostdecryptBuf *bytes.Buffer
	decryptedBuf        *bytes.Buffer
}

func newProtocolConn(c net.Conn, p IProtocol) *protocolConn {
	return &protocolConn{
		Conn:                c,
		IProtocol:           p,
		readBuf:             utils.GetBytes(2048),
		decryptedBuf:        new(bytes.Buffer),
		underPostdecryptBuf: new(bytes.Buffer),
	}
}

func (c *protocolConn) Close() error {
	utils.PutBytes(c.readBuf)
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
	//先吐出已经解密后数据
	if c.decryptedBuf.Len() > 0 {
		return c.decryptedBuf.Read(b)
	}

	n, err = c.Conn.Read(c.readBuf)
	if n == 0 || err != nil {
		return n, err
	}

	c.underPostdecryptBuf.Write(c.readBuf[:n])

	decryptedData, length, err := c.IProtocol.PostDecrypt(c.underPostdecryptBuf.Bytes())
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
	data, err := c.IProtocol.PreEncrypt(b)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
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
