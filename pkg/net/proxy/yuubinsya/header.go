package yuubinsya

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Header struct {
	Addr      netapi.Address
	MigrateID uint64
	Protocol  Protocol
}

// Protocol network type
// +---------+-------+
// |       1 byte    |
// +---------+-------+
// |   5bit  | 3bit  |
// +---------+-------+
// |   opts  |prtocol|
// +---------+-------+
//
// history:
// 66: 0b01000 010
// 77: 0b01001 101
// 78: 0b01001 110
//
// so  0b01000 000, 0b01001 000 is reserved, because it already used on history
//
// 0b00001 000 is reserved for future extension that all opts bits used
type Protocol byte

var (
	TCP  Protocol = 0b00000010 // 2
	Ping Protocol = 0b00000100 // 4
	// Deprecated: use [UDPWithMigrateID]
	UDP Protocol = 0b00000101 // 5
	// UDPWithMigrateID udp with migrate support
	UDPWithMigrateID Protocol = 0b00000110 // 6
)

func (n Protocol) Unknown() bool {
	n = n.Network()
	return n != TCP && n != UDP && n != UDPWithMigrateID && n != Ping
}

func (n Protocol) Network() Protocol {
	return n & 0b00000111
}

func EncodeHeader(password []byte, header Header, buf *pool.Buffer) {
	_ = buf.WriteByte(byte(header.Protocol))

	if header.Protocol.Network() == UDPWithMigrateID {
		_ = pool.BinaryWriteUint64(buf, binary.BigEndian, header.MigrateID)
	}

	_, _ = buf.Write(password)

	if header.Protocol.Network() == TCP || header.Protocol == Ping {
		tools.WriteAddr(header.Addr, buf)
	}
}

func DecodeHeader(password []byte, c pool.BufioConn) (Header, error) {
	header := Header{}

	err := c.BufioRead(func(r *bufio.Reader) error {
		netbyte, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("read net type failed: %w", err)
		}

		header.Protocol = Protocol(netbyte)

		if header.Protocol.Unknown() {
			return fmt.Errorf("unknown network: %d", netbyte)
		}

		if header.Protocol.Network() == UDPWithMigrateID {
			mirgateBytes, err := r.Peek(8)
			if err != nil {
				return fmt.Errorf("read migrate id failed: %w", err)
			}

			_, _ = r.Discard(8)

			header.MigrateID = binary.BigEndian.Uint64(mirgateBytes)
		}

		passwordBuf, err := r.Peek(sha256.Size)
		if err != nil {
			return fmt.Errorf("read password failed: %w", err)
		}

		_, _ = r.Discard(sha256.Size)

		if subtle.ConstantTimeCompare(passwordBuf, password[:]) == 0 {
			return errors.New("password is incorrect")
		}

		if header.Protocol.Network() == TCP || header.Protocol == Ping {
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
