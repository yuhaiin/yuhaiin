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
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// plainHandshaker bytes is password
type plainHandshaker [sha256.Size]byte

func (password plainHandshaker) EncodeHeader(net crypto.Net, buf *bytes.Buffer, addr netapi.Address) {
	buf.WriteByte(byte(net))
	buf.Write(password[:])

	if net == crypto.TCP {
		tools.ParseAddrWriter(addr, buf)
	}
}

func (password plainHandshaker) DecodeHeader(c net.Conn) (crypto.Net, error) {
	z := pool.GetBytesBuffer(ycrypto.Sha256.Size() + 1)
	defer pool.PutBytesBuffer(z)

	if _, err := io.ReadFull(c, z.Bytes()); err != nil {
		return 0, fmt.Errorf("read net type failed: %w", err)
	}
	net := crypto.Net(z.Bytes()[0])

	if net.Unknown() {
		return 0, fmt.Errorf("unknown network: %d", net)
	}

	if subtle.ConstantTimeCompare(z.Bytes()[1:], password[:]) == 0 {
		return 0, errors.New("password is incorrect")
	}

	return net, nil
}

func (plainHandshaker) Handshake(conn net.Conn) (net.Conn, error) { return conn, nil }

func salt(password []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte("+s@1t"))
	return h.Sum(nil)
}

func NewHandshaker(server bool, encrypted bool, password []byte) crypto.Handshaker {
	hash := salt(password)

	if !encrypted {
		return plainHandshaker(hash)
	}

	return ycrypto.NewHandshaker(server, hash, password)
}

func NewAuth(crypt bool, password []byte) (Auth, error) {
	password = salt(password)

	if !crypt {
		return NewPlainAuth(password), nil
	}

	return crypto.GetAuth(password)
}
