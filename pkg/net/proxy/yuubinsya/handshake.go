package yuubinsya

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	ycrypto "github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/entity"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// plainHandshaker bytes is password
type plainHandshaker [sha256.Size]byte

func (password plainHandshaker) StreamHeader(buf *bytes.Buffer, addr netapi.Address) {
	buf.WriteByte(byte(entity.TCP))
	buf.Write(password[:])
	tools.ParseAddrWriter(addr, buf)
}

func (password plainHandshaker) PacketHeader(buf *bytes.Buffer) {
	buf.WriteByte(byte(entity.UDP))
	buf.Write(password[:])
}

func (password plainHandshaker) ParseHeader(c net.Conn) (entity.Net, error) {
	z := pool.GetBytesBuffer(ycrypto.Sha256.Size() + 1)
	defer pool.PutBytesBuffer(z)

	if _, err := io.ReadFull(c, z.Bytes()); err != nil {
		return 0, fmt.Errorf("read net type failed: %w", err)
	}
	net := entity.Net(z.Bytes()[0])

	if net.Unknown() {
		return 0, fmt.Errorf("unknown network: %d", net)
	}

	if subtle.ConstantTimeCompare(z.Bytes()[1:], password[:]) == 0 {
		return 0, errors.New("password is incorrect")
	}

	return net, nil
}

func (plainHandshaker) HandshakeServer(conn net.Conn) (net.Conn, error) { return conn, nil }
func (plainHandshaker) HandshakeClient(conn net.Conn) (net.Conn, error) { return conn, nil }

func salt(password []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte("+s@1t"))
	return h.Sum(nil)
}

func NewHandshaker(encrypted bool, password []byte) entity.Handshaker {
	hash := salt(password)

	if !encrypted {
		return plainHandshaker(hash)
	}

	return ycrypto.NewHandshaker(hash, password)
}

func NewAuth(crypt bool, password []byte) (Auth, error) {
	password = salt(password)

	if !crypt {
		return NewPlainAuth(password), nil
	}

	return crypto.GetAuth(password)
}
