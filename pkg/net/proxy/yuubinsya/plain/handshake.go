package plain

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// Handshaker bytes is password
type Handshaker [sha256.Size]byte

func (password Handshaker) EncodeHeader(net types.Protocol, buf types.Buffer, addr netapi.Address) {
	_ = buf.WriteByte(byte(net))
	_, _ = buf.Write(password[:])

	if net == types.TCP {
		tools.EncodeAddr(addr, buf)
	}
}

func (password Handshaker) DecodeHeader(c net.Conn) (types.Protocol, error) {
	buf := pool.GetBytes(crypto.Sha256.Size() + 1)
	defer pool.PutBytes(buf)

	if _, err := io.ReadFull(c, buf); err != nil {
		return 0, fmt.Errorf("read net type failed: %w", err)
	}
	net := types.Protocol(buf[0])

	if net.Unknown() {
		return 0, fmt.Errorf("unknown network: %d", net)
	}

	if subtle.ConstantTimeCompare(buf[1:], password[:]) == 0 {
		return 0, errors.New("password is incorrect")
	}

	return net, nil
}

func (Handshaker) Handshake(conn net.Conn) (net.Conn, error) { return conn, nil }
