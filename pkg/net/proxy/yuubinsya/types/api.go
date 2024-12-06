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
type Protocol byte

var (
	TCP Protocol = 66
	UDP Protocol = 77
	// UDPWithMigrateID udp with migrate support
	UDPWithMigrateID Protocol = 78
)

func (n Protocol) Unknown() bool { return n != TCP && n != UDP && n != UDPWithMigrateID }

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
