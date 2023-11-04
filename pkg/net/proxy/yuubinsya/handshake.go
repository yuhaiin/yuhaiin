package yuubinsya

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	ycrypto "github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/entity"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// plainHandshaker bytes is password
type plainHandshaker [sha256.Size]byte

func (password plainHandshaker) StreamHeader(buf *bytes.Buffer, addr netapi.Address) {
	buf.WriteByte(byte(entity.TCP))
	buf.Write(password[:])
	s5c.ParseAddrWriter(addr, buf)
}

func (password plainHandshaker) PacketHeader(buf *bytes.Buffer) {
	buf.WriteByte(byte(entity.UDP))
	buf.Write(password[:])
}

func (password plainHandshaker) ParseHeader(c net.Conn) (entity.Net, error) {
	z := pool.GetBytesV2(ycrypto.Sha256.Size() + 1)
	defer pool.PutBytesV2(z)

	if _, err := io.ReadFull(c, z.Bytes()); err != nil {
		return 0, fmt.Errorf("read net type failed: %w", err)
	}
	net := entity.Net(z.Bytes()[0])

	if net.Unknown() {
		return 0, fmt.Errorf("unknown network: %d", net)
	}

	if !bytes.Equal(z.Bytes()[1:], password[:]) {
		return 0, errors.New("password is incorrect")
	}

	return net, nil
}

func (plainHandshaker) HandshakeServer(conn net.Conn) (net.Conn, error) { return conn, nil }
func (plainHandshaker) HandshakeClient(conn net.Conn) (net.Conn, error) { return conn, nil }

func NewHandshaker(encrypted bool, password []byte) entity.Handshaker {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte("+s@1t"))
	hash := h.Sum(nil)

	if !encrypted {
		return plainHandshaker(hash)
	}

	return ycrypto.NewHandshaker(hash, password)
}
