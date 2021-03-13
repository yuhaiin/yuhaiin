package app

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

type connManager struct {
	conns sync.Map

	download      uint64
	upload        uint64
	downloadQueue chan uint64
	uploadQueue   chan uint64
	close         chan bool

	idSeed *idGenerater
}

func newConnManager() *connManager {
	c := &connManager{
		download: 0,
		upload:   0,

		idSeed:        &idGenerater{},
		downloadQueue: make(chan uint64, 10),
		uploadQueue:   make(chan uint64, 10),
		close:         make(chan bool),
	}

	c.startQueue()

	return c
}

func (c *connManager) startQueue() {
	go func() {
		var x uint64
		for {
			select {
			case x = <-c.downloadQueue:
				atomic.AddUint64(&c.download, x)
			case x = <-c.uploadQueue:
				atomic.AddUint64(&c.upload, x)
			case <-c.close:
				return
			}
		}
	}()
}

func (c *connManager) add(i *statisticConn) {
	c.conns.Store(i.id, i)
}

func (c *connManager) delete(id int64) {
	v, _ := c.conns.LoadAndDelete(id)
	if x, ok := v.(*statisticConn); ok {
		fmt.Printf("close id: %d,addr: %s\n", x.id, x.addr)
	}
}

func (c *connManager) Close() {
	close(c.close)
	close(c.downloadQueue)
	close(c.uploadQueue)
}

func (c *connManager) write(w io.Writer, b []byte) (int, error) {
	n, err := w.Write(b)
	c.uploadQueue <- uint64(n)
	return n, err
}

func (c *connManager) read(r io.Reader, b []byte) (int, error) {
	n, err := r.Read(b)
	c.downloadQueue <- uint64(n)
	return n, err
}

func (c *connManager) dc(cn net.Conn, id int64) error {
	c.delete(id)
	return cn.Close()
}

func (c *connManager) newConn(addr string, x net.Conn) net.Conn {
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

type idGenerater struct {
	node int64
	x    sync.Mutex
}

func (i *idGenerater) Generate() (id int64) {
	i.x.Lock()
	defer i.x.Unlock()
	id = i.node
	i.node++
	return
}
