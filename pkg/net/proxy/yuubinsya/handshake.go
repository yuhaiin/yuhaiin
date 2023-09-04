package yuubinsya

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

type handshaker interface {
	handshakeServer(net.Conn) (net.Conn, error)
	handshakeClient(net.Conn) (net.Conn, error)
	streamHeader(buf *bytes.Buffer, addr netapi.Address)
	packetHeader(*bytes.Buffer)
	parseHeader(net.Conn) (Net, error)
}

// plainHandshaker bytes is password
type plainHandshaker [sha256.Size]byte

func (password plainHandshaker) streamHeader(buf *bytes.Buffer, addr netapi.Address) {
	buf.WriteByte(byte(TCP))
	buf.Write(password[:])
	s5c.ParseAddrWriter(addr, buf)
}

func (password plainHandshaker) packetHeader(buf *bytes.Buffer) {
	buf.WriteByte(byte(UDP))
	buf.Write(password[:])
}

func (password plainHandshaker) parseHeader(c net.Conn) (Net, error) {
	z := pool.GetBytesV2(Sha256.Size() + 1)
	defer pool.PutBytesV2(z)

	if _, err := io.ReadFull(c, z.Bytes()); err != nil {
		return 0, fmt.Errorf("read net type failed: %w", err)
	}
	net := Net(z.Bytes()[0])

	if net.Unknown() {
		return 0, fmt.Errorf("unknown network: %d", net)
	}

	if !bytes.Equal(z.Bytes()[1:], password[:]) {
		return 0, errors.New("password is incorrect")
	}

	return net, nil
}

func (plainHandshaker) handshakeServer(conn net.Conn) (net.Conn, error) { return conn, nil }
func (plainHandshaker) handshakeClient(conn net.Conn) (net.Conn, error) { return conn, nil }

type encryptedHandshaker struct {
	signer   Signer
	hash     Hash
	aead     Aead
	password []byte
}

func (t *encryptedHandshaker) streamHeader(buf *bytes.Buffer, addr netapi.Address) {
	buf.Write([]byte{byte(TCP)})
	s5c.ParseAddrWriter(addr, buf)
}
func (t *encryptedHandshaker) packetHeader(buf *bytes.Buffer) { buf.Write([]byte{byte(UDP)}) }

func (t *encryptedHandshaker) parseHeader(c net.Conn) (Net, error) {
	z := make([]byte, 1)

	if _, err := io.ReadFull(c, z); err != nil {
		return 0, fmt.Errorf("read net type failed: %w", err)
	}
	net := Net(z[0])

	if net.Unknown() {
		return 0, fmt.Errorf("unknown network")
	}

	return net, nil
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

	if math.Abs(float64(time.Now().Unix()-int64(binary.BigEndian.Uint64(ttime)))) > 30 { // check time is in +-30s
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
	binary.BigEndian.PutUint64(ttime, uint64(time.Now().Unix()))

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

func (h *encryptedHandshaker) encryptTime(password, salt, dst, src []byte) error {
	nonce := make([]byte, chacha20.NonceSize)
	key := make([]byte, chacha20.KeySize)

	kdf := hkdf.New(h.hash.New, password, salt, []byte{'t', 'i', 'm', 'e'})

	if _, err := io.ReadFull(kdf, key); err != nil {
		return err
	}
	if _, err := io.ReadFull(kdf, nonce); err != nil {
		return err
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}

	cipher.XORKeyStream(dst, src)

	return nil
}

func NewHandshaker(encrypted bool, password []byte) handshaker {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte("+s@1t"))
	hash := h.Sum(nil)

	if !encrypted {
		return plainHandshaker(hash)
	}

	// sha256-hkdf-ecdh-ed25519-chacha20poly1305
	return &encryptedHandshaker{
		NewEd25519(Sha256, hash),
		Sha256,
		Chacha20poly1305,
		password,
	}
}
