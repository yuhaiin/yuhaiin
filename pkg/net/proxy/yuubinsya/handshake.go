package yuubinsya

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/crypto/hkdf"
)

type handshaker interface {
	handshakeServer(net.Conn) (net.Conn, error)
	handshakeClient(net.Conn) (net.Conn, error)
	streamHeader(buf *bytes.Buffer, addr proxy.Address)
	packetHeader(*bytes.Buffer)
}

type plainHandshaker struct{ password []byte }

func (t *plainHandshaker) streamHeader(buf *bytes.Buffer, addr proxy.Address) {
	buf.WriteByte(tcp)
	buf.WriteByte(byte(len(t.password)))
	buf.Write(t.password)
	s5c.ParseAddrWriter(addr, buf)
}

func (t *plainHandshaker) packetHeader(buf *bytes.Buffer) {
	buf.WriteByte(udp)
	buf.WriteByte(byte(len(t.password)))
	buf.Write(t.password)
}

func (t *plainHandshaker) handshakeServer(conn net.Conn) (net.Conn, error) { return conn, nil }
func (t *plainHandshaker) handshakeClient(conn net.Conn) (net.Conn, error) { return conn, nil }

type encryptedHandshaker struct {
	signer Signer
	hash   Hash
	aead   Aead
}

func NewHandshaker(encrypted bool, password []byte) handshaker {
	if !encrypted {
		return &plainHandshaker{password}
	}

	// sha256-hkdf-ecdh-ed25519-chacha20poly1305
	return &encryptedHandshaker{
		NewEd25519(Sha256, password),
		Sha256,
		Chacha20poly1305,
	}
}

func (t *encryptedHandshaker) streamHeader(buf *bytes.Buffer, addr proxy.Address) {
	buf.Write([]byte{tcp, 0})
	s5c.ParseAddrWriter(addr, buf)
}
func (t *encryptedHandshaker) packetHeader(buf *bytes.Buffer) { buf.Write([]byte{udp, 0}) }

func (h *encryptedHandshaker) handshakeClient(conn net.Conn) (net.Conn, error) {
	header := newHeader(h)
	defer header.Def()

	var rpb *ecdh.PublicKey
	var pk *ecdh.PrivateKey
	var err error

	salt := make([]byte, h.hash.Size())
	time := make([]byte, 8*2)

	pk, err = h.send(header, conn, nil)
	if err != nil {
		return nil, err
	}

	copy(salt, header.salt())     // client salt
	copy(time[:8], header.time()) // client time

	rpb, err = h.receive(header, conn, salt)
	if err != nil {
		return nil, err
	}
	copy(time[8:], header.time()) // server time

	if pk.PublicKey().Equal(rpb) {
		return nil, fmt.Errorf("look like replay attack")
	}

	cryptKey, err := pk.ECDH(rpb)
	if err != nil {
		return nil, err
	}

	raead, rnonce, err := h.newAead(cryptKey, salt, time[:8])
	if err != nil {
		return nil, err
	}

	waead, wnonce, err := h.newAead(cryptKey, salt, time[8:])
	if err != nil {
		return nil, err
	}

	return NewConn(conn, rnonce, wnonce, raead, waead), nil
}

func (h *encryptedHandshaker) handshakeServer(conn net.Conn) (net.Conn, error) {
	header := newHeader(h)
	defer header.Def()

	var rpb *ecdh.PublicKey
	var pk *ecdh.PrivateKey
	var err error

	salt := make([]byte, h.hash.Size())
	time := make([]byte, 8*2)

	rpb, err = h.receive(header, conn, nil)
	if err != nil {
		return nil, err
	}

	copy(salt, header.salt())     // client salt
	copy(time[:8], header.time()) // client time

	pk, err = h.send(header, conn, salt)
	if err != nil {
		return nil, err
	}
	copy(time[8:], header.time()) // server time

	if pk.PublicKey().Equal(rpb) {
		return nil, fmt.Errorf("look like replay attack")
	}

	cryptKey, err := pk.ECDH(rpb)
	if err != nil {
		return nil, err
	}

	raead, rnonce, err := h.newAead(cryptKey, salt, time[:8])
	if err != nil {
		return nil, err
	}

	waead, wnonce, err := h.newAead(cryptKey, salt, time[8:])
	if err != nil {
		return nil, err
	}

	return NewConn(conn, wnonce, rnonce, waead, raead), nil
}

func (h *encryptedHandshaker) newAead(cryptKey, salt, time []byte) (cipher.AEAD, []byte, error) {
	keyNonce := make([]byte, h.aead.KeySize()+h.aead.NonceSize())
	if _, err := io.ReadFull(hkdf.New(h.hash.New, cryptKey, salt, append(h.aead.Name(), time...)), keyNonce); err != nil {
		return nil, nil, err
	}
	aead, err := h.aead.New(keyNonce[:h.aead.KeySize()])
	if err != nil {
		return nil, nil, err
	}

	return aead, keyNonce[h.aead.KeySize():], nil
}

func (h *encryptedHandshaker) receive(buf *header, conn net.Conn, salt []byte) (*ecdh.PublicKey, error) {
	_, err := io.ReadFull(conn, buf.Bytes())
	if err != nil {
		return nil, err
	}

	if salt != nil {
		copy(buf.salt(), salt) // client: verify signature with client salt
	}

	if !h.signer.Verify(buf.saltTimeSignature(), buf.signature()) {
		return nil, errors.New("can't verify signature")
	}

	if math.Abs(float64(time.Now().Unix()-int64(binary.BigEndian.Uint64(buf.time())))) > 30 { // check time is in +-30s
		return nil, errors.New("bad timestamp")
	}

	return ecdh.P256().NewPublicKey(buf.publickey())
}

func (h *encryptedHandshaker) send(buf *header, conn net.Conn, salt []byte) (*ecdh.PrivateKey, error) {
	pk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	if salt != nil {
		copy(buf.salt(), salt) // server: sign with client salt
	} else {
		rand.Read(buf.salt()) // client: read random bytes to salt
	}

	copy(buf.publickey(), pk.PublicKey().Bytes())
	binary.BigEndian.PutUint64(buf.time(), uint64(time.Now().Unix()))

	signature, err := h.signer.Sign(rand.Reader, buf.saltTimeSignature())
	if err != nil {
		return nil, err
	}

	copy(buf.signature(), signature)

	if salt != nil {
		rand.Read(buf.salt()) // server: read random bytes to padding
	}

	if _, err = conn.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	return pk, nil
}

type header struct {
	bytes *pool.Bytes
	th    *encryptedHandshaker
}

func newHeader(h *encryptedHandshaker) *header {
	return &header{pool.GetBytesV2(h.hash.Size() + 8 + h.signer.SignatureSize() + 65), h}
}
func (h *header) Bytes() []byte { return h.bytes.Bytes() }
func (h *header) signature() []byte {
	return h.Bytes()[:h.th.signer.SignatureSize()]
}
func (h *header) publickey() []byte {
	return h.Bytes()[h.th.hash.Size()+8+h.th.signer.SignatureSize():]
}
func (h *header) time() []byte {
	return h.Bytes()[h.th.hash.Size()+h.th.signer.SignatureSize() : h.th.hash.Size()+8+h.th.signer.SignatureSize()]
}
func (h *header) salt() []byte {
	return h.Bytes()[h.th.signer.SignatureSize() : h.th.signer.SignatureSize()+h.th.hash.Size()]
}
func (h *header) saltTimeSignature() []byte {
	return h.Bytes()[h.th.signer.SignatureSize():]
}
func (h *header) Def() { defer pool.PutBytesV2(h.bytes) }
