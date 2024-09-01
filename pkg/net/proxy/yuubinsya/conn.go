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
	w := pool.NewBufferSize(min(len(payload), nat.MaxSegmentSize) + 1024)
	defer w.Reset()
	err := c.payloadToBuffer(w, payload, addr)
	if err != nil {
		return 0, err
	}
	_, err = c.BufioConn.Write(w.Bytes())
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *PacketConn) payloadToBuffer(w *pool.Buffer, payload []byte, addr net.Addr) error {
	length := min(len(payload), nat.MaxSegmentSize)

	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return fmt.Errorf("failed to parse addr: %w", err)
	}

	tools.EncodeAddr(taddr, w)
	_ = binary.Write(w, binary.BigEndian, uint16(length))
	_, _ = w.Write(payload[:length])

	return nil
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

type Conn struct {
	net.Conn

	addr        netapi.Address
	handshaker  types.Handshaker
	headerWrote bool
}

func newConn(con net.Conn, addr netapi.Address, handshaker types.Handshaker) net.Conn {
	return &Conn{
		Conn:       con,
		addr:       addr,
		handshaker: handshaker,
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.headerWrote {
		return c.Conn.Write(b)
	}

	c.headerWrote = true

	buf := pool.NewBufferSize(1024 + len(b))
	defer buf.Reset()

	c.handshaker.EncodeHeader(types.Header{Protocol: types.TCP, Addr: c.addr}, buf)
	_, _ = buf.Write(b)

	if n, err := c.Conn.Write(buf.Bytes()); err != nil {
		return n, err
	}

	return len(b), nil
}
