package hysteria2

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
)

type hopSocket struct {
	conn   net.PacketConn
	remote *net.UDPAddr
}

type hopPacket struct {
	data []byte
	err  error
}

// This deliberately implements only PacketConn: QUIC must use WriteTo to
// select the current relay, including when the address family changes.
type addressHopPacketConn struct {
	addr      *addressHopAddr
	interval  udphop.HopIntervalConfig
	listen    func(context.Context, net.Addr) (net.PacketConn, error)
	ctx       context.Context
	cancel    context.CancelFunc
	packets   chan hopPacket
	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error

	mu              sync.Mutex
	current         hopSocket
	previous        hopSocket
	targetIndex     int
	writeDeadline   time.Time
	readDeadline    pipe.PipeDeadline
	readBufferSize  int
	writeBufferSize int
	closed          bool
}

func newAddressHopPacketConn(setup, lifetime context.Context, addr *addressHopAddr, interval udphop.HopIntervalConfig, listen func(context.Context, net.Addr) (net.PacketConn, error)) (*addressHopPacketConn, error) {
	ctx, cancel := context.WithCancel(lifetime)
	c := &addressHopPacketConn{
		addr: addr, interval: interval, listen: listen, ctx: ctx, cancel: cancel,
		packets: make(chan hopPacket, 128), done: make(chan struct{}),
		readDeadline: pipe.MakePipeDeadline(), targetIndex: rand.IntN(len(addr.targets)),
	}
	remote := c.remote(c.targetIndex)
	conn, err := listen(setup, remote)
	if err != nil {
		cancel()
		return nil, err
	}
	c.current = hopSocket{conn: conn, remote: remote}
	c.wg.Add(2)
	go c.receive(conn)
	go c.hopLoop()
	return c, nil
}

func (c *addressHopPacketConn) remote(index int) *net.UDPAddr {
	target := c.addr.targets[index]
	return &net.UDPAddr{IP: target.ip, Port: int(target.ports[rand.IntN(len(target.ports))])}
}

func (c *addressHopPacketConn) hopLoop() {
	defer c.wg.Done()
	timer := time.NewTimer(c.nextInterval())
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-timer.C:
			c.hop()
			timer.Reset(c.nextInterval())
		}
	}
}

func (c *addressHopPacketConn) nextInterval() time.Duration {
	if c.interval.Min == c.interval.Max {
		return c.interval.Min
	}
	return c.interval.Min + time.Duration(rand.Int64N(int64(c.interval.Max-c.interval.Min)+1))
}

func (c *addressHopPacketConn) hop() {
	c.mu.Lock()
	if c.closed || c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	index := c.targetIndex
	if count := len(c.addr.targets); count > 1 {
		// Always change IP when multiple resolved relay IPs are available.
		index = (index + 1 + rand.IntN(count-1)) % count
	}
	c.mu.Unlock()
	remote := c.remote(index)
	ctx, cancel := context.WithTimeout(c.ctx, configuration.Timeout)
	defer cancel()
	conn, err := c.listen(ctx, remote)
	if err != nil {
		return // Keep the current path if opening a new socket fails.
	}
	c.mu.Lock()
	if c.closed || c.ctx.Err() != nil {
		c.mu.Unlock()
		_ = conn.Close()
		return
	}
	if err := conn.SetWriteDeadline(c.writeDeadline); err != nil {
		c.mu.Unlock()
		_ = conn.Close()
		return
	}
	if c.readBufferSize != 0 {
		_ = setHopReadBuffer(conn, c.readBufferSize)
	}
	if c.writeBufferSize != 0 {
		_ = setHopWriteBuffer(conn, c.writeBufferSize)
	}
	previous := c.previous.conn
	c.previous = c.current
	c.current = hopSocket{conn: conn, remote: remote}
	c.targetIndex = index
	c.wg.Add(1)
	go c.receive(conn)
	c.mu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
}

func (c *addressHopPacketConn) receive(conn net.PacketConn) {
	defer c.wg.Done()
	var buf [2048]byte
	for {
		n, _, err := conn.ReadFrom(buf[:])
		if err != nil {
			c.mu.Lock()
			current := !c.closed && c.current.conn == conn
			c.mu.Unlock()
			if current {
				select {
				case c.packets <- hopPacket{err: err}:
				case <-c.done:
				}
			}
			return
		}
		packet := hopPacket{data: pool.Clone(buf[:n])}
		select {
		case <-c.done:
			pool.PutBytes(packet.data)
			return
		case c.packets <- packet:
		default:
			pool.PutBytes(packet.data)
		}
	}
}

func (c *addressHopPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case packet := <-c.packets:
		if packet.err != nil {
			return 0, nil, packet.err
		}
		n := copy(b, packet.data)
		pool.PutBytes(packet.data)
		return n, c.addr, nil
	}
}

func (c *addressHopPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	socket := c.current
	c.mu.Unlock()
	return socket.conn.WriteTo(b, socket.remote)
}

func (c *addressHopPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel() // Interrupt an in-progress socket open before waiting for it.
		c.mu.Lock()
		c.closed = true
		close(c.done)
		current, previous := c.current.conn, c.previous.conn
		c.mu.Unlock()
		c.closeErr = current.Close()
		if previous != nil {
			c.closeErr = errors.Join(c.closeErr, previous.Close())
		}
		c.wg.Wait()
		c.readDeadline.Set(time.Time{})
		for {
			select {
			case packet := <-c.packets:
				pool.PutBytes(packet.data)
			default:
				return
			}
		}
	})
	return c.closeErr
}

func (c *addressHopPacketConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current.conn.LocalAddr()
}

func (c *addressHopPacketConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *addressHopPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline.Set(t)
	return nil
}

func (c *addressHopPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeDeadline = t
	err := c.current.conn.SetWriteDeadline(t)
	if c.previous.conn != nil {
		err = errors.Join(err, c.previous.conn.SetWriteDeadline(t))
	}
	return err
}

func (c *addressHopPacketConn) SetReadBuffer(size int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readBufferSize = size
	return setHopReadBuffer(c.current.conn, size)
}

func (c *addressHopPacketConn) SetWriteBuffer(size int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeBufferSize = size
	return setHopWriteBuffer(c.current.conn, size)
}

func setHopReadBuffer(conn net.PacketConn, size int) error {
	if setter, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		return setter.SetReadBuffer(size)
	}
	return nil
}

func setHopWriteBuffer(conn net.PacketConn, size int) error {
	if setter, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		return setter.SetWriteBuffer(size)
	}
	return nil
}
