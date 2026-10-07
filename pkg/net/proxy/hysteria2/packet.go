package hysteria2

import (
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	hyclient "github.com/apernet/hysteria/core/v2/client"
)

type datagram struct {
	data []byte
	addr string
}

type packetConn struct {
	conn          hyclient.HyUDPConn
	local         net.Addr
	done          chan struct{}
	packets       chan datagram
	readDeadline  pipe.PipeDeadline
	writeDeadline pipe.PipeDeadline
	writeMu       sync.Mutex // Upstream HyUDPConn.Send is not safe for concurrent writes.
	closeOnce     sync.Once
}

func newPacketConn(conn hyclient.HyUDPConn, local net.Addr) *packetConn {
	p := &packetConn{conn: conn, local: local, done: make(chan struct{}), packets: make(chan datagram, 128), readDeadline: pipe.MakePipeDeadline(), writeDeadline: pipe.MakePipeDeadline()}
	go p.receive()
	return p
}

func (p *packetConn) receive() {
	defer close(p.packets)
	for {
		data, addr, err := p.conn.Receive()
		if err != nil {
			return
		}
		select {
		case <-p.done:
			return
		case p.packets <- datagram{data, addr}:
		default: // UDP is unreliable; bound memory when the application stops reading.
		}
	}
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-p.done:
		return 0, nil, net.ErrClosed
	case <-p.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case <-p.done:
		return 0, nil, net.ErrClosed
	case <-p.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case packet, ok := <-p.packets:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		addr, err := netapi.ParseAddress("udp", packet.addr)
		if err != nil {
			return 0, nil, err
		}
		return copy(b, packet.data), addr, nil
	}
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	select {
	case <-p.done:
		return 0, net.ErrClosed
	case <-p.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if len(b) > 65507 {
		return 0, syscall.EMSGSIZE
	}
	if addr == nil {
		return 0, &net.AddrError{Err: "missing UDP destination"}
	}
	if err := p.conn.Send(b, addr.String()); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetConn) Close() error {
	p.closeOnce.Do(func() { close(p.done); _ = p.conn.Close() })
	return nil
}

func (p *packetConn) LocalAddr() net.Addr { return p.local }
func (p *packetConn) SetDeadline(t time.Time) error {
	_ = p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}
func (p *packetConn) SetReadDeadline(t time.Time) error  { p.readDeadline.Set(t); return nil }
func (p *packetConn) SetWriteDeadline(t time.Time) error { p.writeDeadline.Set(t); return nil }
