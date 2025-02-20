package yuubinsya

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type PacketConn struct {
	handshaker types.Handshaker
	pool.BufioConn
}

func newPacketConn(conn pool.BufioConn, handshaker types.Handshaker) *PacketConn {
	x := &PacketConn{
		BufioConn:  conn,
		handshaker: handshaker,
	}
	return x
}

// Handshake Handshake
// only used for client
func (c *PacketConn) Handshake(migrateID uint64) (uint64, error) {
	protocol := types.UDPWithMigrateID
	w := pool.NewBufferSize(1024)
	defer w.Reset()
	c.handshaker.EncodeHeader(types.Header{Protocol: protocol, MigrateID: migrateID}, w)
	_, err := c.BufioConn.Write(w.Bytes())
	if err != nil {
		return 0, err
	}

	if protocol == types.UDPWithMigrateID {
		var id uint64
		err := c.BufioConn.BufioRead(func(r *bufio.Reader) error {
			idbytes, err := r.Peek(8)
			if err != nil {
				return fmt.Errorf("read net type failed: %w", err)
			}
			_, _ = r.Discard(8)
			id = binary.BigEndian.Uint64(idbytes)

			return nil
		})

		return id, err
	}

	return 0, nil
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	bufLen := len(payload)
	if bufLen > nat.MaxSegmentSize {
		return 0, fmt.Errorf("payload too large: %d > %d", bufLen, nat.MaxSegmentSize)
	}

	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	buf := pool.GetBytes(bufLen + tools.MaxAddrLength + 2)
	defer pool.PutBytes(buf)

	addrLen := tools.EncodeAddr(taddr, buf)
	binary.BigEndian.PutUint16(buf[addrLen:], uint16(bufLen))
	copy(buf[addrLen+2:], payload)

	_, err = c.BufioConn.Write(buf[:bufLen+addrLen+2])
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *PacketConn) WriteBack(b []byte, addr net.Addr) (int, error) {
	return c.WriteTo(b, addr)
}

// func (c *PacketConn) WriteBatch(payloads ...netapi.WriteBatchBuf) error {
// 	w := pool.NewBufferSize(20000)
// 	defer w.Reset()

// 	for _, p := range payloads {
// 		err := c.payloadToBuffer(w, p.Payload, p.Addr)
// 		if err != nil {
// 			log.Error("payload to buffer failed", "err", err)
// 		}
// 	}

// 	_, err := c.BufioConn.Write(w.Bytes())
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	var addr netapi.Address
	err = c.BufioRead(func(r *bufio.Reader) error {
		_, addr, err = tools.ReadAddr("udp", r)
		if err != nil {
			return fmt.Errorf("failed to resolve udp packet addr: %w", err)
		}

		l, err := r.Peek(2)
		if err != nil {
			return fmt.Errorf("peek length failed: %w", err)
		}

		_, _ = r.Discard(2)
		length := binary.BigEndian.Uint16(l)

		offset := min(len(payload), int(length))

		n, err = io.ReadFull(r, payload[:offset])
		if err != nil {
			return fmt.Errorf("read data failed: %w", err)
		}

		if length > uint16(n) {
			_, err = r.Discard(int(length) - n)
			if err != nil {
				return fmt.Errorf("discard data failed: %w", err)
			}
		}

		return nil
	})

	return n, addr, err
}
