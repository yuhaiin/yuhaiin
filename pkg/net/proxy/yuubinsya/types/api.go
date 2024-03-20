package types

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type Protocol byte

var (
	TCP Protocol = 66
	UDP Protocol = 77
)

func (n Protocol) Unknown() bool { return n != TCP && n != UDP }

type Buffer interface {
	Len() int
	Bytes() []byte
	Write(b []byte) (int, error)
	WriteByte(b byte) error
}

type Handshaker interface {
	Handshake(net.Conn) (net.Conn, error)
	EncodeHeader(Protocol, Buffer, netapi.Address)
	DecodeHeader(net.Conn) (Protocol, error)
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

func Salt(password []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte("+s@1t"))
	return h.Sum(nil)
}
