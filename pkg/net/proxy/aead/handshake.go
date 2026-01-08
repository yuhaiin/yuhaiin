package aead

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/crypto/chacha20"
)

type encryptedHandshaker struct {
	signer                 Signer
	hash                   Hash
	aead                   Aead
	password, passwordHash []byte
	server                 bool
}

func (h *encryptedHandshaker) Handshake(conn net.Conn) (net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second * 30))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	if h.server {
		return h.handshakeServer(conn)
	}

	return h.handshakeClient(conn)
}

func (h *encryptedHandshaker) handshakeClient(conn net.Conn) (net.Conn, error) {
	header := newHeader(h)
	defer header.Def()

	salt := make([]byte, h.hash.Size())

	pk, time1, err := h.send(header, conn, nil)
	if err != nil {
		return nil, err
	}

	copy(salt, header.salt()) // client salt

	rpb, time2, err := h.receive(header, conn, salt)
	if err != nil {
		return nil, err
	}

	if pk.PublicKey().Equal(rpb) {
		return nil, fmt.Errorf("look like replay attack")
	}

	cryptKey, err := pk.ECDH(rpb)
	if err != nil {
		return nil, err
	}

	raead, rnonce, err := h.newAead(cryptKey, salt, time1)
	if err != nil {
		return nil, err
	}

	waead, wnonce, err := h.newAead(cryptKey, salt, time2)
	if err != nil {
		return nil, err
	}

	return NewConn(conn, rnonce, wnonce, raead, waead), nil
}

func (h *encryptedHandshaker) handshakeServer(conn net.Conn) (net.Conn, error) {
	header := newHeader(h)
	defer header.Def()

	salt := make([]byte, h.hash.Size())

	rpb, time1, err := h.receive(header, conn, nil)
	if err != nil {
		return nil, err
	}

	copy(salt, header.salt()) // client salt

	pk, time2, err := h.send(header, conn, salt)
	if err != nil {
		return nil, err
	}

	if pk.PublicKey().Equal(rpb) {
		return nil, fmt.Errorf("look like replay attack")
	}

	cryptKey, err := pk.ECDH(rpb)
	if err != nil {
		return nil, err
	}

	raead, rnonce, err := h.newAead(cryptKey, salt, time1)
	if err != nil {
		return nil, err
	}

	waead, wnonce, err := h.newAead(cryptKey, salt, time2)
	if err != nil {
		return nil, err
	}

	return NewConn(conn, wnonce, rnonce, waead, raead), nil
}

func (h *encryptedHandshaker) newAead(cryptKey, salt, time []byte) (cipher.AEAD, []byte, error) {
	prk, err := hkdf.Extract(h.hash.New, cryptKey, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("extract prk failed: %w", err)
	}

	keyNonce, err := hkdf.Expand(h.hash.New, prk,
		string(append(h.aead.Name(), time...)),
		h.aead.KeySize()+h.aead.NonceSize())
	if err != nil {
		return nil, nil, fmt.Errorf("expand keyNonce failed: %w", err)
	}

	aead, err := h.aead.New(keyNonce[:h.aead.KeySize()])
	if err != nil {
		return nil, nil, err
	}

	return aead, keyNonce[h.aead.KeySize():], nil
}

func (h *encryptedHandshaker) receive(buf *header, conn net.Conn, salt []byte) (_ *ecdh.PublicKey, ttime []byte, _ error) {
	_, err := io.ReadFull(conn, buf.Bytes())
	if err != nil {
		return nil, nil, err
	}

	if salt != nil {
		copy(buf.salt(), salt) // client: verify signature with client salt
	}

	if !h.signer.Verify(buf.saltTimeSignature(), buf.signature()) {
		return nil, nil, errors.New("can't verify signature")
	}

	ttime = make([]byte, 8)
	if err = h.encryptTime(h.password, buf.salt(), ttime, buf.time()); err != nil {
		return nil, nil, fmt.Errorf("decrypt time failed: %w", err)
	}

	if math.Abs(float64(system.NowUnix()-int64(binary.BigEndian.Uint64(ttime)))) > 30 { // check time is in +-30s
		return nil, nil, errors.New("bad timestamp")
	}

	pubkey, err := ecdh.P256().NewPublicKey(buf.publickey())
	if err != nil {
		return nil, nil, err
	}

	return pubkey, ttime, nil
}

func (h *encryptedHandshaker) send(buf *header, conn net.Conn, salt []byte) (_ *ecdh.PrivateKey, ttime []byte, _ error) {
	pk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	if salt != nil {
		copy(buf.salt(), salt) // server: sign with client salt
	} else {
		if _, err = rand.Read(buf.salt()); err != nil { // client: read random bytes to salt
			return nil, nil, fmt.Errorf("read salt from rand failed: %w", err)
		}
	}

	copy(buf.publickey(), pk.PublicKey().Bytes())

	ttime = make([]byte, 8)
	binary.BigEndian.PutUint64(ttime, uint64(system.NowUnix()))

	if err = h.encryptTime(h.password, buf.salt(), buf.time(), ttime); err != nil {
		return nil, nil, fmt.Errorf("encrypt time failed: %w", err)
	}

	signature, err := h.signer.Sign(rand.Reader, buf.saltTimeSignature())
	if err != nil {
		return nil, nil, err
	}

	copy(buf.signature(), signature)

	if salt != nil {
		if _, err := rand.Read(buf.salt()); err != nil { // server: read random bytes to padding
			return nil, nil, fmt.Errorf("read salt from rand failed: %w", err)
		}
	}

	if _, err = conn.Write(buf.Bytes()); err != nil {
		return nil, nil, err
	}

	return pk, ttime, nil
}

type header struct {
	th    *encryptedHandshaker
	bytes []byte
}

func newHeader(h *encryptedHandshaker) *header {
	return &header{h, pool.GetBytes(h.hash.Size() + 8 + h.signer.SignatureSize() + 65)}
}
func (h *header) Bytes() []byte { return h.bytes }
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
func (h *header) Def() { defer pool.PutBytes(h.bytes) }

func (h *encryptedHandshaker) encryptTime(password, salt, dst, src []byte) error {
	prk, err := hkdf.Extract(h.hash.New, password, salt)
	if err != nil {
		return fmt.Errorf("extract prk failed: %w", err)
	}

	keyNonce, err := hkdf.Expand(h.hash.New,
		prk, "time", chacha20.NonceSize+chacha20.KeySize)
	if err != nil {
		return fmt.Errorf("expand keyNonce failed: %w", err)
	}

	key := keyNonce[:chacha20.KeySize]
	nonce := keyNonce[chacha20.KeySize:]

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}

	cipher.XORKeyStream(dst, src)

	return nil
}

func NewHandshaker(server bool, password []byte, method node.AeadCryptoMethod) *encryptedHandshaker {
	var aead Aead
	switch method {
	case node.AeadCryptoMethod_XChacha20Poly1305:
		aead = XChacha20poly1305
	default:
		aead = Chacha20poly1305
	}

	passwordHash := Salt(password)

	// sha256-hkdf-ecdh-ed25519-chacha20poly1305
	return &encryptedHandshaker{
		signer:       NewEd25519(Sha256, passwordHash),
		hash:         Sha256,
		aead:         aead,
		password:     password,
		passwordHash: passwordHash,
		server:       server,
	}
}
