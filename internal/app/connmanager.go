package app

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

var _ proxy.Proxy = (*connManager)(nil)

type connManager struct {
	conns    sync.Map
	download uint64
	upload   uint64
	idSeed   *idGenerater
	proxy    proxy.Proxy
}

func newConnManager(p proxy.Proxy) *connManager {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	c := &connManager{
		download: 0,
		upload:   0,

		idSeed: &idGenerater{},
		proxy:  p,
	}

	return c
}

func (c *connManager) SetProxy(p proxy.Proxy) {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	c.proxy = p
}

func (c *connManager) GetDownload() uint64 {
	return atomic.LoadUint64(&c.download)
}

func (c *connManager) GetUpload() uint64 {
	return atomic.LoadUint64(&c.upload)
}

func (c *connManager) add(i *statisticConn) {
	c.conns.Store(i.id, i)
}

func (c *connManager) addPacketConn(i *statisticPacketConn) {
	c.conns.Store(i.id, i)
}

func (c *connManager) delete(id int64) {
	v, _ := c.conns.LoadAndDelete(id)
	if x, ok := v.(*statisticConn); ok {
		fmt.Printf("close tcp conn id: %d,addr: %s\n", x.id, x.addr)
	}
	if x, ok := v.(*statisticPacketConn); ok {
		fmt.Printf("close packet conn id: %d,addr: %s\n", x.id, x.addr)
	}
}

func (c *connManager) write(w io.Writer, b []byte) (int, error) {
	n, err := w.Write(b)
	atomic.AddUint64(&c.upload, uint64(n))
	return n, err
}

func (c *connManager) writeTo(w net.PacketConn, b []byte, addr net.Addr) (int, error) {
	n, err := w.WriteTo(b, addr)
	atomic.AddUint64(&c.upload, uint64(n))
	return n, err
}

func (c *connManager) readFrom(r net.PacketConn, b []byte) (int, net.Addr, error) {
	n, addr, err := r.ReadFrom(b)
	atomic.AddUint64(&c.download, uint64(n))
	return n, addr, err
}

func (c *connManager) read(r io.Reader, b []byte) (int, error) {
	n, err := r.Read(b)
	atomic.AddUint64(&c.download, uint64(n))
	return n, err
}

func (c *connManager) dc(cn net.Conn, id int64) error {
	c.delete(id)
	return cn.Close()
}

func (c *connManager) dpc(cn net.PacketConn, id int64) error {
	c.delete(id)
	return cn.Close()
}

func (c *connManager) newConn(addr string, x net.Conn) net.Conn {
	if x == nil {
		return nil
	}
	s := &statisticConn{
		id:    c.idSeed.Generate(),
		addr:  addr,
		Conn:  x,
		close: c.dc,
		write: c.write,
		read:  c.read,
	}

	c.add(s)

	return s
}

func (c *connManager) newPacketConn(addr string, x net.PacketConn) net.PacketConn {
	if x == nil {
		return nil
	}
	s := &statisticPacketConn{
		id:         c.idSeed.Generate(),
		addr:       addr,
		PacketConn: x,
		close:      c.dpc,
		writeTo:    c.writeTo,
		readFrom:   c.readFrom,
	}

	c.addPacketConn(s)

	return s
}

func (c *connManager) Conn(host string) (net.Conn, error) {
	conn, err := c.proxy.Conn(host)
	return c.newConn(host, conn), err
}

func (c *connManager) PacketConn(host string) (net.PacketConn, error) {
	conn, err := c.proxy.PacketConn(host)
	return c.newPacketConn(host, conn), err
}

var _ net.Conn = (*statisticConn)(nil)

type statisticConn struct {
	net.Conn
	close func(net.Conn, int64) error
	write func(io.Writer, []byte) (int, error)
	read  func(io.Reader, []byte) (int, error)

	id   int64
	addr string
}

func (s *statisticConn) Close() error {
	return s.close(s.Conn, s.id)
}

func (s *statisticConn) Write(b []byte) (n int, err error) {
	return s.write(s.Conn, b)
}

func (s *statisticConn) Read(b []byte) (n int, err error) {
	return s.read(s.Conn, b)
}

var _ net.PacketConn = (*statisticPacketConn)(nil)

type statisticPacketConn struct {
	net.PacketConn
	close    func(net.PacketConn, int64) error
	writeTo  func(net.PacketConn, []byte, net.Addr) (n int, err error)
	readFrom func(net.PacketConn, []byte) (n int, addr net.Addr, err error)

	id   int64
	addr string
}

func (s *statisticPacketConn) Close() error {
	return s.close(s.PacketConn, s.id)
}

func (s *statisticPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return s.writeTo(s.PacketConn, p, addr)
}

func (s *statisticPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return s.readFrom(s.PacketConn, p)
}

type idGenerater struct {
	node int64
}

func (i *idGenerater) Generate() (id int64) {
	return atomic.AddInt64(&i.node, 1)
}
