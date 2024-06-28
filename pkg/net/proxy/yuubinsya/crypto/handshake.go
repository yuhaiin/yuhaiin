package crypto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

type encryptedHandshaker struct {
	signer   types.Signer
	hash     types.Hash
	aead     types.Aead
	password []byte
	server   bool
}

func (t *encryptedHandshaker) EncodeHeader(net types.Protocol, buf types.Buffer, addr netapi.Address) {
	_, _ = buf.Write([]byte{byte(net)})

	if net == types.TCP {
		tools.EncodeAddr(addr, buf)
	}
}

func (t *encryptedHandshaker) DecodeHeader(c net.Conn) (types.Protocol, error) {
	z := make([]byte, 1)

	if _, err := io.ReadFull(c, z); err != nil {
		return 0, fmt.Errorf("read net type failed: %w", err)
	}
	net := types.Protocol(z[0])

	if net.Unknown() {
		return 0, fmt.Errorf("unknown network")
	}

	return net, nil
}

func (h *encryptedHandshaker) Handshake(conn net.Conn) (net.Conn, error) {
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

func NewHandshaker(server bool, hash []byte, password []byte) *encryptedHandshaker {
	// sha256-hkdf-ecdh-ed25519-chacha20poly1305
	return &encryptedHandshaker{
		signer:   NewEd25519(Sha256, hash),
		hash:     Sha256,
		aead:     Chacha20poly1305,
		password: password,
		server:   server,
	}
}
