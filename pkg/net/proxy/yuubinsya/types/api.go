package types

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Header struct {
	Addr      netapi.Address
	MigrateID uint64
	Protocol  Protocol
}

// Protocol network type
// +---------+-------+
// |       1 byte    |
// +---------+-------+
// |   5bit  | 3bit  |
// +---------+-------+
// |   opts  |prtocol|
// +---------+-------+
//
// history:
// 66: 0b01000 010
// 77: 0b01001 101
// 78: 0b01001 110
//
// so  0b01000 000, 0b01001 000 is reserved, because it already used on history
//
// 0b00001 000 is reserved for future extension that all opts bits used
type Protocol byte

var (
	TCP Protocol = 0b00000010 // 2
	// Deprecated: use UDPWithMigrateID
	UDP Protocol = 0b00000101 // 5
	// UDPWithMigrateID udp with migrate support
	UDPWithMigrateID Protocol = 0b00000110 // 6
)

func (n Protocol) Unknown() bool {
	n = n.Network()
	return n != TCP && n != UDP && n != UDPWithMigrateID
}

func (n Protocol) Network() Protocol {
	return n & 0b00000111
}

type Buffer interface {
	Len() int
	Bytes() []byte
	Write(b []byte) (int, error)
	WriteByte(b byte) error
}

type PacketBuffer interface {
	Buffer
	Advance(int)
	Retreat(i int)
}

type Handshaker interface {
	Handshake(net.Conn) (net.Conn, error)
	EncodeHeader(Header, Buffer)
	DecodeHeader(pool.BufioConn) (Header, error)
}

type Hash interface {
	New() hash.Hash
	Size() int
}

type Signer interface {
	Sign(rand io.Reader, digest []byte) (signature []byte, err error)
	SignatureSize() int
	Verify(message, sig []byte) bool
}

type Aead interface {
	New([]byte) (cipher.AEAD, error)
	KeySize() int
	NonceSize() int
	Name() []byte
}

type Auth interface {
	cipher.AEAD
	KeySize() int
	Key() []byte
}

func AuthHeaderSize(auth Auth, prefix bool) int {
	var a int

	if auth != nil {
		a = auth.NonceSize() + auth.KeySize() + auth.Overhead()
	}

	if prefix {
		a += 3
	}

	return a
}

func Salt(password []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte("+s@1t"))
	return h.Sum(nil)
}
