package plain

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
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

	if header.Protocol.Network() == types.UDPWithMigrateID {
		_ = pool.BinaryWriteUint64(buf, binary.BigEndian, header.MigrateID)
	}

	_, _ = buf.Write(password[:])

	if header.Protocol.Network() == types.TCP {
		tools.WriteAddr(header.Addr, buf)
	}
}

func (password Handshaker) DecodeHeader(c pool.BufioConn) (types.Header, error) {
	header := types.Header{}

	err := c.BufioRead(func(r *bufio.Reader) error {
		netbyte, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("read net type failed: %w", err)
		}

		header.Protocol = types.Protocol(netbyte)

		if header.Protocol.Unknown() {
			return fmt.Errorf("unknown network: %d", netbyte)
		}

		if header.Protocol.Network() == types.UDPWithMigrateID {
			mirgateBytes, err := r.Peek(8)
			if err != nil {
				return fmt.Errorf("read migrate id failed: %w", err)
			}

			_, _ = r.Discard(8)

			header.MigrateID = binary.BigEndian.Uint64(mirgateBytes)
		}

		passwordBuf, err := r.Peek(crypto.Sha256.Size())
		if err != nil {
			return fmt.Errorf("read password failed: %w", err)
		}

		_, _ = r.Discard(crypto.Sha256.Size())

		if subtle.ConstantTimeCompare(passwordBuf, password[:]) == 0 {
			return errors.New("password is incorrect")
		}

		if header.Protocol.Network() == types.TCP {
			_, target, err := tools.ReadAddr("tcp", r)
			if err != nil {
				return fmt.Errorf("read addr failed: %w", err)
			}

			header.Addr = target
		}

		return nil
	})

	return header, err
}

func (Handshaker) Handshake(conn net.Conn) (net.Conn, error) { return conn, nil }
