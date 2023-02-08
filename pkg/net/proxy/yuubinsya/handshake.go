package yuubinsya

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/crypto/hkdf"
)

type handshaker interface {
	handshake(net.Conn) (net.Conn, error)
	streamHeader(buf *bytes.Buffer, addr proxy.Address)
	packetHeader(*bytes.Buffer)
}

type tlsHandshaker struct{ password []byte }

func (t *tlsHandshaker) streamHeader(buf *bytes.Buffer, addr proxy.Address) {
	buf.WriteByte(tcp)
	buf.WriteByte(byte(len(t.password)))
	buf.Write(t.password)
	s5c.ParseAddrWriter(addr, buf)
}

func (t *tlsHandshaker) packetHeader(buf *bytes.Buffer) {
	buf.WriteByte(udp)
	buf.WriteByte(byte(len(t.password)))
	buf.Write(t.password)
}

func (t *tlsHandshaker) handshake(conn net.Conn) (net.Conn, error) { return conn, nil }

type traditionHandshaker struct {
	server bool
	signer Signer
	hash   Hash
	aead   Aead
}

func NewHandshaker(server, tls bool, password []byte) handshaker {
	if tls {
		return &tlsHandshaker{password: password}
	}

	// sha256-hkdf-ecdh-ed25519-chacha20poly1305
	return &traditionHandshaker{
		server: server,
		hash:   Sha256,
		signer: NewEd25519(Sha256, password),
		aead:   Chacha20poly1305,
	}
}

func (t *traditionHandshaker) streamHeader(buf *bytes.Buffer, addr proxy.Address) {
	buf.Write([]byte{tcp, 0})
	s5c.ParseAddrWriter(addr, buf)
}
func (t *traditionHandshaker) packetHeader(buf *bytes.Buffer) { buf.Write([]byte{udp, 0}) }

func (h *traditionHandshaker) handshake(conn net.Conn) (net.Conn, error) {
	header := newHeader(h)
	defer header.Def()

	var rpb *ecdh.PublicKey
	var pk *ecdh.PrivateKey
	var err error

	salt := make([]byte, h.hash.Size())

	if h.server {
		rpb, err = h.receive(header, conn, nil)
		if err != nil {
			return nil, err
		}

		copy(salt, header.salt())

		pk, err = h.send(header, conn, salt)
		if err != nil {
			return nil, err
		}
	} else {
		pk, err = h.send(header, conn, nil)
		if err != nil {
			return nil, err
		}

		copy(salt, header.salt())

		rpb, err = h.receive(header, conn, salt)
		if err != nil {
			return nil, err
		}
	}

	if pk.PublicKey().Equal(rpb) {
		return nil, fmt.Errorf("look like replay attack")
	}

	cryptKey, err := pk.ECDH(rpb)
	if err != nil {
		return nil, err
	}

	key := make([]byte, h.aead.KeySize())
	if _, err := io.ReadFull(hkdf.New(h.hash.New, cryptKey, salt, h.aead.Name()), key); err != nil {
		return nil, err
	}

	aead, err := h.aead.New(key)
	if err != nil {
		return nil, err
	}

	return NewConn(conn, aead), nil
}

func (h *traditionHandshaker) receive(buf *header, conn net.Conn, salt []byte) (*ecdh.PublicKey, error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, err := io.ReadFull(conn, buf.Bytes())
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}

	if salt != nil {
		copy(buf.salt(), salt)
	}

	if !h.signer.Verify(buf.saltSignature(), buf.signature()) {
		return nil, errors.New("can't verify signature")
	}

	return ecdh.P256().NewPublicKey(buf.publickey())
}

func (h *traditionHandshaker) send(buf *header, conn net.Conn, salt []byte) (*ecdh.PrivateKey, error) {
	pk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	if salt != nil {
		copy(buf.salt(), salt)
	} else {
		rand.Read(buf.salt())
	}

	copy(buf.publickey(), pk.PublicKey().Bytes())

	signature, err := h.signer.Sign(rand.Reader, buf.saltSignature())
	if err != nil {
		return nil, err
	}

	copy(buf.signature(), signature)

	if salt != nil {
		rand.Read(buf.salt())
	}

	if _, err = conn.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	return pk, nil
}

type header struct {
	bytes *pool.Bytes
	th    *traditionHandshaker
}

func newHeader(h *traditionHandshaker) *header {
	return &header{pool.GetBytesV2(h.hash.Size() + h.signer.SignatureSize() + 65), h}
}
func (h *header) Bytes() []byte { return h.bytes.Bytes() }
func (h *header) signature() []byte {
	return h.Bytes()[:h.th.signer.SignatureSize()]
}
func (h *header) publickey() []byte {
	return h.Bytes()[h.th.hash.Size()+h.th.signer.SignatureSize():]
}
func (h *header) salt() []byte {
	return h.Bytes()[h.th.signer.SignatureSize() : h.th.signer.SignatureSize()+h.th.hash.Size()]
}
func (h *header) saltSignature() []byte {
	return h.Bytes()[h.th.signer.SignatureSize():]
}
func (h *header) Def() { defer pool.PutBytesV2(h.bytes) }
