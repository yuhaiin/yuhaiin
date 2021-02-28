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

	idSeed *idGenerater
}

func newConnManager() *connManager {
	c := &connManager{
		download: 0,
		upload:   0,

		idSeed:        &idGenerater{},
		downloadQueue: make(chan uint64, 5),
		uploadQueue:   make(chan uint64, 5),
	}

	c.startQueue()

	return c
}

func (c *connManager) startQueue() {
	go func() {
		for s := range c.downloadQueue {
			atomic.AddUint64(&c.download, s)
		}
	}()

	go func() {
		for s := range c.uploadQueue {
			atomic.AddUint64(&c.upload, s)
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

func (c *connManager) addDownload(i uint64) {
	go func() {
		c.downloadQueue <- i
	}()
}

func (c *connManager) addUpload(i uint64) {
	go func() {
		c.uploadQueue <- i
	}()
}

func (c *connManager) Write(b []byte, w io.Writer) (int, error) {
	n, err := w.Write(b)
	c.addUpload(uint64(n))
	return n, err
}

func (c *connManager) Read(b []byte, r io.Reader) (int, error) {
	n, err := r.Read(b)
	c.addDownload(uint64(n))
	return n, err

}

func (c *connManager) newConn(addr string, x net.Conn) net.Conn {
	s := &statisticConn{
		id:   c.idSeed.Generate(),
		addr: addr,
		Conn: x,
	}

	s.close = func() error {
		c.delete(s.id)
		return s.Conn.Close()
	}

	s.write = func(b []byte) (int, error) {
		n, err := s.Conn.Write(b)
		c.addUpload(uint64(n))
		return n, err
	}

	s.read = func(b []byte) (int, error) {
		n, err := s.Conn.Read(b)
		c.addDownload(uint64(n))
		return n, err
	}

	c.add(s)

	return s
}

type statisticConn struct {
	net.Conn
	close func() error
	write func([]byte) (int, error)
	read  func([]byte) (int, error)

	id   int64
	addr string
}

func (s *statisticConn) Close() error {
	return s.close()
}

func (s *statisticConn) Write(b []byte) (int, error) {
	return s.write(b)
}

func (s *statisticConn) Read(b []byte) (int, error) {
	return s.read(b)
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
