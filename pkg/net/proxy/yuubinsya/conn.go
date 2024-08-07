package yuubinsya

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

var closedBufioReader = bufio.NewReaderSize(bytes.NewReader(nil), 10)

type PacketConn struct {
	net.Conn
	handshaker types.Handshaker
	bufior     *bufio.Reader
	rmux       sync.Mutex
	closed     bool
}

func newPacketConn(conn net.Conn, handshaker types.Handshaker) *PacketConn {
	x := &PacketConn{
		Conn:       conn,
		bufior:     pool.GetBufioReader(conn, 5000),
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
	_, err := c.Conn.Write(w.Bytes())
	if err != nil {
		return 0, err
	}

	if protocol == types.UDPWithMigrateID {
		c.rmux.Lock()
		defer c.rmux.Unlock()

		id, err := c.bufior.Peek(8)
		if err != nil {
			return 0, fmt.Errorf("read net type failed: %w", err)
		}
		_, _ = c.bufior.Discard(8)
		return binary.BigEndian.Uint64(id), nil
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
	_, err = c.Conn.Write(w.Bytes())
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

func (c *PacketConn) WriteBatch(payloads ...netapi.WriteBatchBuf) error {
	w := pool.NewBufferSize(20000)
	defer w.Reset()

	for _, p := range payloads {
		err := c.payloadToBuffer(w, p.Payload, p.Addr)
		if err != nil {
			log.Error("payload to buffer failed", "err", err)
		}
	}

	_, err := c.Conn.Write(w.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (c *PacketConn) Close() error {
	c.closed = true
	err := c.Conn.Close()

	c.rmux.Lock()
	bufio := c.bufior
	c.bufior = closedBufioReader
	pool.PutBufioReader(bufio)
	c.rmux.Unlock()

	return err
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	if c.closed {
		return 0, nil, net.ErrClosed
	}

	c.rmux.Lock()
	defer c.rmux.Unlock()

	_, addr, err := tools.ReadAddr("udp", c.bufior)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}

	l, err := c.bufior.Peek(2)
	if err != nil {
		return 0, nil, fmt.Errorf("peek length failed: %w", err)
	}

	_, _ = c.bufior.Discard(2)
	length := binary.BigEndian.Uint16(l)

	n, err = io.ReadFull(c.bufior, payload[:min(len(payload), int(length))])
	if err != nil {
		return n, nil, fmt.Errorf("read data failed: %w", err)
	}

	_, err = c.bufior.Discard(int(length) - n)
	if err != nil {
		return n, nil, fmt.Errorf("discard data failed: %w", err)
	}

	return n, addr, nil
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
