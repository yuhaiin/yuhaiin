package plain

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// Handshaker bytes is password
type Handshaker [sha256.Size]byte

func (password Handshaker) EncodeHeader(header types.Header, buf types.Buffer) {
	_ = buf.WriteByte(byte(header.Protocol))

	if header.Protocol == types.UDPWithMigrateID {
		_ = binary.Write(buf, binary.BigEndian, header.MigrateID)
	}

	_, _ = buf.Write(password[:])

	if header.Protocol == types.TCP {
		tools.EncodeAddr(header.Addr, buf)
	}
}

func (password Handshaker) DecodeHeader(c net.Conn) (types.Header, error) {
	buf := pool.GetBytes(crypto.Sha256.Size())
	defer pool.PutBytes(buf)

	if _, err := io.ReadFull(c, buf[:1]); err != nil {
		return types.Header{}, fmt.Errorf("read net type failed: %w", err)
	}
	net := types.Protocol(buf[0])

	if net.Unknown() {
		return types.Header{}, fmt.Errorf("unknown network")
	}

	header := types.Header{
		Protocol: net,
	}

	if net == types.UDPWithMigrateID {
		if _, err := io.ReadFull(c, buf[:8]); err != nil {
			return types.Header{}, fmt.Errorf("read net type failed: %w", err)
		}

		header.MigrateID = binary.BigEndian.Uint64(buf[:8])
	}

	if _, err := io.ReadFull(c, buf); err != nil {
		return types.Header{}, fmt.Errorf("read password failed: %w", err)
	}

	if subtle.ConstantTimeCompare(buf, password[:]) == 0 {
		return header, errors.New("password is incorrect")
	}

	if net == types.TCP {
		target, err := tools.ResolveAddr(c)
		if err != nil {
			return types.Header{}, fmt.Errorf("resolve addr failed: %w", err)
		}
		defer pool.PutBytes(target)

		header.Addr = target.Address("tcp")
	}

	return header, nil
}

func (Handshaker) Handshake(conn net.Conn) (net.Conn, error) { return conn, nil }
