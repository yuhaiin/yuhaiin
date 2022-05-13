package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
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

// CMD types
const (
	CmdTCP byte = 1
	CmdUDP byte = 2
)

var _ net.Conn = (*Conn)(nil)

// Client vmess client
type Client struct {
	users    []*User
	count    int
	opt      byte
	security byte

	isAead bool
}

// Conn is a connection to vmess server
type Conn struct {
	user     *User
	opt      byte
	security byte

	atyp Atyp
	addr Addr
	port Port

	reqBodyIV   [16]byte
	reqBodyKey  [16]byte
	reqRespV    byte
	respBodyIV  [16]byte
	respBodyKey [16]byte

	net.Conn
	dataReader io.ReadCloser
	dataWriter writer

	isAead bool
	udp    bool
}

// NewClient .
func NewClient(uuidStr, security string, alterID int) (*Client, error) {
	uuid, err := StrToUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	c := &Client{isAead: alterID == 0}

	user := NewUser(uuid)
	c.users = append(c.users, user)
	c.users = append(c.users, user.GenAlterIDUsers(alterID)...)
	c.count = len(c.users)

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

	// NOTE: give rand a new seed to avoid the same sequence of values
	rand.Seed(time.Now().UnixNano())

	return c, nil
}

func (c *Client) NewConn(rc net.Conn, target string) (net.Conn, error) {
	conn, err := c.newConn(rc, "tcp", target)
	if err != nil {
		rc.Close()
		return nil, err
	}

	return &vmessConn{Conn: conn}, nil
}

func (c *Client) NewPacketConn(rc net.Conn, target string) (net.PacketConn, error) {
	conn, err := c.newConn(rc, "udp", target)
	if err != nil {
		return nil, err
	}

	return &vmessPacketConn{Conn: conn}, nil
}

// NewConn .
func (c *Client) newConn(rc net.Conn, network, target string) (*Conn, error) {
	conn := &Conn{
		isAead: c.isAead,
		user:   c.users[rand.Intn(c.count)], opt: c.opt, security: c.security, udp: network == "udp"}
	var err error
	conn.atyp, conn.addr, conn.port, err = ParseAddr(target)
	if err != nil {
		return nil, err
	}

	randBytes := make([]byte, 33)
	rand.Read(randBytes)

	copy(conn.reqBodyIV[:], randBytes[:16])
	copy(conn.reqBodyKey[:], randBytes[16:32])
	conn.reqRespV = randBytes[32]

	if !c.isAead {
		// !none aead
		conn.respBodyIV = md5.Sum(conn.reqBodyIV[:])
		conn.respBodyKey = md5.Sum(conn.reqBodyKey[:])

		// AuthInfo
		_, err = rc.Write(conn.EncodeAuthInfo())
		if err != nil {
			return nil, err
		}
	} else {
		// aead
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

// EncodeAuthInfo returns HMAC("md5", UUID, UTC) result
func (c *Conn) EncodeAuthInfo() []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().UTC().Unix()))

	h := hmac.New(md5.New, c.user.UUID[:])
	h.Write(ts)

	return h.Sum(nil)
}

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
	paddingLen := rand.Intn(16)
	pSec := byte(paddingLen<<4) | c.security // P(4bit) and Sec(4bit)
	buf.WriteByte(pSec)

	buf.WriteByte(0) // reserved
	if c.udp {
		buf.WriteByte(CmdUDP)
	} else {
		buf.WriteByte(CmdTCP) // cmd
	}

	// target
	err := binary.Write(buf, binary.BigEndian, uint16(c.port)) // port
	if err != nil {
		return nil, err
	}

	buf.WriteByte(byte(c.atyp)) // atyp
	buf.Write(c.addr)           // addr

	// padding
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		rand.Read(padding)
		buf.Write(padding)
	}

	// F
	fnv1a := fnv.New32a()
	_, err = fnv1a.Write(buf.Bytes())
	if err != nil {
		return nil, err
	}
	buf.Write(fnv1a.Sum(nil))

	if !c.isAead {
		// !none aead
		block, err := aes.NewCipher(c.user.CmdKey[:])
		if err != nil {
			return nil, err
		}

		stream := cipher.NewCFBEncrypter(block, TimestampHash(time.Now().UTC()))
		stream.XORKeyStream(buf.Bytes(), buf.Bytes())
		return buf.Bytes(), nil
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
	if c.dataWriter != nil {
		return c.dataWriter.Write(b)
	}

	c.initWriter()
	return c.dataWriter.Write(b)
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
		c.dataReader.Close()
	}

	if c.dataWriter != nil {
		c.dataWriter.Close()
	}

	return c.Conn.Close()
}

var _ net.Conn = (*vmessConn)(nil)
var _ io.ReaderFrom = (*vmessConn)(nil)
var _ io.WriterTo = (*vmessConn)(nil)

type vmessConn struct {
	*Conn
}

func (v *vmessConn) ReadFrom(r io.Reader) (int64, error) {
	if v.dataWriter != nil {
		return v.dataWriter.ReadFrom(r)
	}

	v.initWriter()
	return v.dataWriter.ReadFrom(r)
}

func (v *vmessConn) WriteTo(w io.Writer) (int64, error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)
	return io.CopyBuffer(w, v.Conn, buf)
}

var _ net.PacketConn = (*vmessPacketConn)(nil)

type vmessPacketConn struct {
	*Conn
}

func (c *vmessPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}

func (c *vmessPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.Write(b)
}
