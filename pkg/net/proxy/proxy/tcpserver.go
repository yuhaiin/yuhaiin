package proxy

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TCPServer tcp server common
type TCPServer struct {
	host string
	lock sync.Mutex

	listener net.Listener
	proxy    atomic.Value
	handle   func(net.Conn, Proxy)
}

// NewTCPServer create new TCP listener
func NewTCPServer(host string, handle func(net.Conn, Proxy)) (Server, error) {
	if handle == nil {
		return nil, errors.New("handle is must")
	}

	s := &TCPServer{
		host:   host,
		handle: handle,
		proxy:  atomic.Value{},
	}

	if host == "" {
		return s, nil
	}

	err := s.run()
	if err != nil {
		return nil, fmt.Errorf("server Run -> %v", err)
	}
	return s, nil
}

func (t *TCPServer) SetServer(host string) (err error) {
	if t.host == host {
		return
	}
	_ = t.Close()

	t.lock.Lock()
	defer t.lock.Unlock()

	if host == "" {
		return
	}

	t.host = host

	fmt.Println("SetServer create new server")
	return t.run()
}

func (t *TCPServer) SetProxy(p Proxy) {
	t.proxy.Store(p)
}

func (t *TCPServer) getProxy() Proxy {
	y, ok := t.proxy.Load().(Proxy)
	if ok {
		return y
	}
	return &DefaultProxy{}
}

func (t *TCPServer) GetListenHost() string {
	return t.host
}

func (t *TCPServer) run() (err error) {
	fmt.Println("New TCP Server:", t.host)
	t.listener, err = net.Listen("tcp", t.host)
	if err != nil {
		return fmt.Errorf("TcpServer:run() -> %v", err)
	}

	go func() {
		err := t.process()
		if err != nil {
			log.Println(err)
		}
	}()
	return
}

func (t *TCPServer) process() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	var tempDelay time.Duration
	for {
		c, err := t.listener.Accept()
		if err != nil {
			// from https://golang.org/src/net/http/server.go?s=93655:93701#L2977
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}

				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}

				log.Printf("tcp sever: Accept error: %v; retrying in %v\n", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			if errors.Is(err, net.ErrClosed) {
				log.Printf("checked tcp server closed: %v\n", err)
			} else {
				log.Printf("tcp server accept failed: %v\n", err)
			}
			return fmt.Errorf("tcp server accept failed: %v", err)
		}

		tempDelay = 0

		go func() {
			defer c.Close()
			t.handle(c, t.getProxy())
		}()
	}
}

func (t *TCPServer) Close() error {
	if t.listener == nil {
		return nil
	}
	return t.listener.Close()
}
