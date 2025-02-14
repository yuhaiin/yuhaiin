package vmess

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand/v2"
	"net"
	"runtime"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
)

// Request Options
const (
	OptBasicFormat byte = 0
	OptChunkStream byte = 1
	// OptReuseTCPConnection byte = 2
	// OptMetadataObfuscate  byte = 4
)

// Security types
const (
	SecurityAES128GCM        byte = 3
	SecurityChacha20Poly1305 byte = 4
	SecurityNone             byte = 5
)

type CMD byte

// CMD types
const (
	CmdTCP CMD = 1
	CmdUDP CMD = 2
)

func (c CMD) Byte() byte { return byte(c) }

var _ net.Conn = (*Conn)(nil)

// Client vmess client
type Client struct {
	users    []*User
	opt      byte
	security byte

	isAead bool
}

// Conn is a connection to vmess server
type Conn struct {
	addr address

	net.Conn
	dataReader io.ReadCloser
	dataWriter writer

	user *User

	reqBodyIV   [16]byte
	reqBodyKey  [16]byte
	respBodyIV  [16]byte
	respBodyKey [16]byte

	opt      byte
	security byte

	reqRespV byte

	isAead bool
	CMD    CMD
}

// NewClient .
func newClient(uuidStr, security string, alterID int) (*Client, error) {
	uuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return nil, err
	}

	c := &Client{isAead: alterID == 0}

	user := NewUser(uuid)
	c.users = append(c.users, user)
	c.users = append(c.users, user.GenAlterIDUsers(alterID)...)

	c.opt = OptChunkStream

	security = strings.ToLower(security)
	switch security {
	case "aes-128-gcm":
		c.security = SecurityAES128GCM
	case "chacha20-poly1305":
		c.security = SecurityChacha20Poly1305
	case "none":
		c.security = SecurityNone
	case "auto":
		fallthrough
	case "":
		c.security = SecurityChacha20Poly1305
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "s390x" || runtime.GOARCH == "arm64" {
			c.security = SecurityAES128GCM
		}
		// NOTE: use basic format when no method specified
		// c.opt = OptBasicFormat
		// c.security = SecurityNone
	default:
		return nil, errors.New("unknown security type: " + security)
	}

	return c, nil
}

func (c *Client) NewConn(rc net.Conn, dst netapi.Address) (net.Conn, error) {
	return c.newConn(rc, CmdTCP, dst)
}

func (c *Client) NewPacketConn(rc net.Conn, dst netapi.Address) (net.PacketConn, error) {
	return c.newConn(rc, CmdUDP, dst)
}

// NewConn .
func (c *Client) newConn(rc net.Conn, cmd CMD, dst netapi.Address) (*Conn, error) {
	conn := &Conn{
		isAead:   c.isAead,
		user:     c.users[rand.IntN(len(c.users))],
		opt:      c.opt,
		security: c.security,
		CMD:      cmd,
		addr:     address{dst},
	}

	randBytes := make([]byte, 33)
	_, _ = crand.Read(randBytes)

	copy(conn.reqBodyIV[:], randBytes[:16])
	copy(conn.reqBodyKey[:], randBytes[16:32])
	conn.reqRespV = randBytes[32]

	if !c.isAead {
		conn.respBodyIV = md5.Sum(conn.reqBodyIV[:])
		conn.respBodyKey = md5.Sum(conn.reqBodyKey[:])
	} else {
		rbIV := sha256.Sum256(conn.reqBodyIV[:])
		copy(conn.respBodyIV[:], rbIV[:16])
		rbKey := sha256.Sum256(conn.reqBodyKey[:])
		copy(conn.respBodyKey[:], rbKey[:16])
	}

	// Request
	req, err := conn.EncodeRequest()
	if err != nil {
		return nil, err
	}

	_, err = rc.Write(req)
	if err != nil {
		return nil, err
	}

	conn.Conn = rc

	return conn, nil
}

func (c *Conn) RemoteAddr() net.Addr { return c.addr }

// EncodeRequest encodes requests to network bytes
func (c *Conn) EncodeRequest() ([]byte, error) {

	buf := new(bytes.Buffer)

	// Request
	buf.WriteByte(1)           // Ver
	buf.Write(c.reqBodyIV[:])  // IV
	buf.Write(c.reqBodyKey[:]) // Key
	buf.WriteByte(c.reqRespV)  // V
	buf.WriteByte(c.opt)       // Opt

	// pLen and Sec
	paddingLen := rand.IntN(16)
	buf.WriteByte(byte(paddingLen<<4) | c.security) // P(4bit) and Sec(4bit)

	buf.WriteByte(0) // reserved

	buf.WriteByte(c.CMD.Byte()) // cmd

	// target
	_ = pool.BinaryWriteUint16(buf, binary.BigEndian, uint16(c.addr.Port())) // port

	buf.WriteByte(byte(c.addr.Type())) // atyp
	buf.Write(c.addr.Bytes())          // addr

	// padding
	if paddingLen > 0 {
		_, _ = relay.CopyN(buf, crand.Reader, int64(paddingLen))
	}

	// F
	fnv1a := fnv.New32a()
	fnv1a.Write(buf.Bytes())
	buf.Write(fnv1a.Sum(nil))

	if !c.isAead {
		now := system.NowUnix()
		block, err := aes.NewCipher(c.user.CmdKey[:])
		if err != nil {
			return nil, err
		}
		stream := cipher.NewCFBEncrypter(block, TimestampHash(now))
		stream.XORKeyStream(buf.Bytes(), buf.Bytes())

		abuf := new(bytes.Buffer)
		ts := make([]byte, 8)
		binary.BigEndian.PutUint64(ts, uint64(now))
		abuf.Write(ssr.Hmac(crypto.MD5, c.user.UUID[:], ts, nil))
		abuf.Write(buf.Bytes())
		return abuf.Bytes(), nil
	}

	// aead
	var fixedLengthCmdKey [16]byte
	copy(fixedLengthCmdKey[:], c.user.CmdKey[:])
	vmessout := SealVMessAEADHeader(fixedLengthCmdKey, buf.Bytes())
	return vmessout, nil
}

// DecodeRespHeader .
func (c *Conn) DecodeRespHeader() error {
	var buf []byte
	if !c.isAead {
		// !none aead
		block, err := aes.NewCipher(c.respBodyKey[:])
		if err != nil {
			return err
		}

		stream := cipher.NewCFBDecrypter(block, c.respBodyIV[:])

		buf = make([]byte, 4)
		_, err = io.ReadFull(c.Conn, buf)
		if err != nil {
			return err
		}

		stream.XORKeyStream(buf, buf)
	} else {
		var err error
		buf, err = DecodeResponseHeader(c.respBodyKey[:], c.respBodyIV[:], c.Conn)
		if err != nil {
			return fmt.Errorf("decode response header failed: %w", err)
		}
		if len(buf) < 4 {
			return errors.New("unexpected buffer length")
		}
	}

	if buf[0] != c.reqRespV {
		return errors.New("unexpected response header")
	}

	// TODO: Dynamic port support
	if buf[2] != 0 {
		// dataLen := int32(buf[3])
		return errors.New("dynamic port is not supported now")
	}

	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	for {
		if c.dataWriter != nil {
			return c.dataWriter.Write(b)
		}

		c.initWriter()
	}
}

func (c *Conn) initWriter() {
	c.dataWriter = &connWriter{Conn: c.Conn}
	if c.opt&OptChunkStream == OptChunkStream {
		switch c.security {
		case SecurityNone:
			c.dataWriter = ChunkedWriter(c.Conn)

		case SecurityAES128GCM:
			block, _ := aes.NewCipher(c.reqBodyKey[:])
			aead, _ := cipher.NewGCM(block)
			c.dataWriter = AEADWriter(c.Conn, aead, c.reqBodyIV[:])

		case SecurityChacha20Poly1305:
			key := make([]byte, 32)
			t := md5.Sum(c.reqBodyKey[:])
			copy(key, t[:])
			t = md5.Sum(key[:16])
			copy(key[16:], t[:])
			aead, _ := chacha20poly1305.New(key)
			c.dataWriter = AEADWriter(c.Conn, aead, c.reqBodyIV[:])
		}
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.dataReader != nil {
		return c.dataReader.Read(b)
	}

	err = c.DecodeRespHeader()
	if err != nil {
		return 0, err
	}

	c.dataReader = c.Conn
	if c.opt&OptChunkStream == OptChunkStream {
		switch c.security {
		case SecurityNone:
			c.dataReader = ChunkedReader(c.Conn)

		case SecurityAES128GCM:
			block, err := aes.NewCipher(c.respBodyKey[:])
			if err != nil {
				return 0, fmt.Errorf("new aes cipher failed: %w", err)
			}
			aead, err := cipher.NewGCM(block)
			if err != nil {
				return 0, fmt.Errorf("new gcm failed: %w", err)
			}
			c.dataReader = AEADReader(c.Conn, aead, c.respBodyIV[:])

		case SecurityChacha20Poly1305:
			key := make([]byte, 32)
			t := md5.Sum(c.respBodyKey[:])
			copy(key, t[:])
			t = md5.Sum(key[:16])
			copy(key[16:], t[:])
			aead, err := chacha20poly1305.New(key)
			if err != nil {
				return 0, fmt.Errorf("new chacha20poly1305 failed: %w", err)
			}
			c.dataReader = AEADReader(c.Conn, aead, c.respBodyIV[:])
		}
	}

	return c.dataReader.Read(b)
}

func (c *Conn) Close() error {
	if c.dataReader != nil {
		defer c.dataReader.Close()
	}

	if c.dataWriter != nil {
		defer c.dataWriter.Close()
	}

	return c.Conn.Close()
}

func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}

func (c *Conn) WriteTo(b []byte, target net.Addr) (int, error) {
	t, err := netapi.ParseSysAddr(target)
	if err != nil {
		return 0, err
	}

	if t.String() != c.addr.Address.String() {
		return 0, fmt.Errorf("vmess only support symmetric NAT")
	}

	return c.Write(b)
}
