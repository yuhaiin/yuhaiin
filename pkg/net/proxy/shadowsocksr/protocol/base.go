package protocol

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/cipher"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type protocol interface {
	EncryptStream(dst *pool.Buffer, data []byte) error
	DecryptStream(dst *pool.Buffer, data []byte) (int, error)
	EncryptPacket(data []byte) ([]byte, error)
	DecryptPacket(data []byte) ([]byte, error)

	GetOverhead() int
}

type errorProtocol struct{ error }

func NewErrorProtocol(err error) protocol                                  { return &errorProtocol{err} }
func (e *errorProtocol) EncryptStream(dst *pool.Buffer, data []byte) error { return e.error }
func (e *errorProtocol) DecryptStream(dst *pool.Buffer, data []byte) (int, error) {
	return 0, e.error
}
func (e *errorProtocol) EncryptPacket(data []byte) ([]byte, error) { return nil, e.error }
func (e *errorProtocol) DecryptPacket(data []byte) ([]byte, error) { return nil, e.error }
func (e *errorProtocol) GetOverhead() int                          { return 0 }

type AuthData struct {
	mu           sync.Mutex
	clientID     [4]byte
	connectionID uint32
}

func NewAuth() *AuthData { return &AuthData{} }

// nextAuth reserves a unique connection ID and snapshots its client ID under
// the same lock. The shared AuthData is used by concurrent SSR connections.
func (a *AuthData) nextAuth() ([4]byte, uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.connectionID == 0 || a.connectionID > 0xFF000000 {
		_, _ = crand.Read(a.clientID[:])
		a.connectionID = rand.Uint32() & 0xFFFFFF
	} else {
		a.connectionID++
	}
	return a.clientID, a.connectionID
}

type packetConn struct {
	protocol protocol
	net.PacketConn
}

func newPacketConn(conn net.PacketConn, p protocol) net.PacketConn { return &packetConn{p, conn} }

func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	data, err := c.protocol.EncryptPacket(b)
	if err != nil {
		return 0, err
	}
	n, err := c.PacketConn.WriteTo(data, addr)
	if err != nil {
		return 0, err
	}
	if n != len(data) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	decoded, err := c.protocol.DecryptPacket(b[:n])
	if err != nil {
		return 0, addr, err
	}
	if len(decoded) > len(b) {
		return 0, addr, io.ErrShortBuffer
	}
	copy(b, decoded)
	return len(decoded), addr, nil
}

func (c *packetConn) Close() error { return c.PacketConn.Close() }

type conn struct {
	protocol protocol
	net.Conn

	readMu, writeMu sync.Mutex

	ciphertext, plaintext pool.Buffer
}

func newConn(c net.Conn, p protocol) net.Conn {
	return &conn{
		Conn:     c,
		protocol: p,
	}
}

func (c *conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.plaintext.Len() > 0 {
		return c.plaintext.Read(b)
	}

	// A TCP read is not a protocol frame. Keep fetching ciphertext until
	// the decoder produces plaintext or the underlying stream terminates.
	for {
		n, readErr := c.Conn.Read(b)
		if n > 0 {
			_, _ = c.ciphertext.Write(b[:n])
			consumed, err := c.protocol.DecryptStream(&c.plaintext, c.ciphertext.Bytes())
			if err != nil {
				c.ciphertext.Reset()
				return 0, err
			}
			if consumed < 0 || consumed > c.ciphertext.Len() {
				return 0, fmt.Errorf("ssr protocol consumed invalid ciphertext length %d", consumed)
			}
			c.ciphertext.Next(consumed)
			if c.plaintext.Len() > 0 {
				n, _ = c.plaintext.Read(b)
				return n, nil
			}
		}
		if readErr != nil {
			if readErr == io.EOF && c.ciphertext.Len() != 0 {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, readErr
		}
		if n == 0 {
			return 0, io.ErrNoProgress
		}
	}
}

func (c *conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	buf := pool.NewBufferSize(len(b) + 1024)
	defer buf.Reset()

	if err := c.protocol.EncryptStream(buf, b); err != nil {
		return 0, err
	}
	data := buf.Bytes()
	for len(data) > 0 {
		n, err := c.Conn.Write(data)
		if err != nil {
			return 0, err
		}
		if n <= 0 {
			return 0, io.ErrShortWrite
		}
		data = data[n:]
	}
	return len(b), nil
}

var ProtocolMethod = map[string]func(Protocol) protocol{
	"auth_aes128_sha1": NewAuthAES128SHA1,
	"auth_aes128_md5":  NewAuthAES128MD5,
	"auth_chain_a":     NewAuthChainA,
	"auth_chain_b":     NewAuthChainB,
	"origin":           NewOrigin,
	"auth_sha1_v4":     NewAuthSHA1v4,
	"verify_sha1":      NewVerifySHA1,
	"ota":              NewVerifySHA1,
}

type Protocol struct {
	*cipher.Cipher

	Auth  *AuthData
	Name  string
	Param string
	IV    []byte

	HeadSize     int
	TcpMss       int
	ObfsOverhead int
}

func (s Protocol) stream() (protocol, error) {
	c, ok := ProtocolMethod[strings.ToLower(s.Name)]
	if ok {
		return c(s), nil
	}
	return nil, fmt.Errorf("protocol %s not found", s.Name)
}

func (s Protocol) Stream(c net.Conn, iv []byte) (net.Conn, error) {
	z := s
	z.IV = iv

	p, err := z.stream()
	if err != nil {
		return nil, err
	}
	return newConn(c, p), nil
}

func (s Protocol) Packet(c net.PacketConn) (net.PacketConn, error) {
	p, err := s.stream()
	if err != nil {
		return nil, err
	}
	return newPacketConn(c, p), nil
}

func (s *Protocol) SetHeadLen(data []byte, defaultValue int) {
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
