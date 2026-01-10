package yuubinsya

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type PacketConn struct {
	pool.BufioConn
	ctx          context.Context
	coalesceChan chan []byte
	cancel       context.CancelCauseFunc
	hash         []byte
	coalesce     bool
}

func newPacketConn(conn pool.BufioConn, hash []byte, coalesce bool) *PacketConn {
	ctx, cancel := context.WithCancelCause(context.Background())
	x := &PacketConn{
		BufioConn:    conn,
		hash:         hash,
		coalesceChan: make(chan []byte, 100),
		ctx:          ctx,
		cancel:       cancel,
		coalesce:     coalesce,
	}

	if coalesce {
		go x.loopflush()
	}

	return x
}

func NewPacketConn(conn pool.BufioConn) *PacketConn {
	return newPacketConn(conn, nil, false)
}

// handshake handshake
// only used for client
func (c *PacketConn) handshake(migrateID uint64) (uint64, error) {
	protocol := UDPWithMigrateID
	w := pool.NewBufferSize(1024)
	defer w.Reset()
	EncodeHeader(c.hash, Header{Protocol: protocol, MigrateID: migrateID}, w)
	_, err := c.Write(w.Bytes())
	if err != nil {
		return 0, err
	}

	if protocol == UDPWithMigrateID {
		var id uint64
		err := c.BufioRead(func(r *bufio.Reader) error {
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
	if c.coalesce {
		return c.WriteToCoalesce(payload, addr)
	}

	return c.WriteToOne(payload, addr)
}

func (c *PacketConn) WriteToOne(payload []byte, addr net.Addr) (int, error) {
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

	return c.Write(buf[:bufLen+addrLen+2])
}

func (c *PacketConn) WriteToCoalesce(payload []byte, addr net.Addr) (int, error) {
	bufLen := len(payload)
	if bufLen > nat.MaxSegmentSize {
		return 0, fmt.Errorf("payload too large: %d > %d", bufLen, nat.MaxSegmentSize)
	}

	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	buf := pool.GetBytes(bufLen + tools.MaxAddrLength + 2)

	addrLen := tools.EncodeAddr(taddr, buf)
	binary.BigEndian.PutUint16(buf[addrLen:], uint16(bufLen))
	copy(buf[addrLen+2:], payload)

	select {
	case c.coalesceChan <- buf[:bufLen+addrLen+2]:
		return len(payload), nil
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}

func (c *PacketConn) loopflush() {
	buffSize := max(configuration.RelayBufferSize.Load(), configuration.UDPBufferSize.Load())

	buf := pool.NewBufferSize(buffSize * 2)
	defer buf.Reset()

	for {
		select {
		case <-c.ctx.Done():
			return
		case first := <-c.coalesceChan:
			buf.Truncate(0)

			c.flush(first, buf, buffSize)
		}
	}
}

func (c *PacketConn) flush(first []byte, buffer *pool.Buffer, buffSize int) {
	defer pool.PutBytes(first)

	var buf []byte

	if len(c.coalesceChan) == 0 {
		buf = first
	} else {
		_, _ = buffer.Write(first)

		drainLoop:
			for {
				select {
				case <-c.ctx.Done():
					return
				case b := <-c.coalesceChan:
					_, _ = buffer.Write(b)
					pool.PutBytes(b)
					if buffer.Len() > buffSize {
						break drainLoop
					}
				default:
					break drainLoop
				}
			}

		buf = buffer.Bytes()
	}

	if _, err := c.Write(buf); err != nil {
		c.cancel(err)
		log.Error("write to failed", "err", err)
	}
}

func (c *PacketConn) WriteBack(b []byte, addr net.Addr) (int, error) {
	return c.WriteTo(b, addr)
}

func (c *PacketConn) Close() error {
	c.cancel(io.EOF)
	return c.BufioConn.Close()
}

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

func Salt(password []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte("+s@1t"))
	return h.Sum(nil)
}
