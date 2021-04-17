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

type UDPServer struct {
	host string
	lock sync.Mutex

	listener net.PacketConn
	handle   func([]byte, Proxy) ([]byte, error)
	proxy    atomic.Value
}

func (u *UDPServer) SetProxy(f Proxy) {
	u.proxy.Store(f)
}

func (u *UDPServer) getProxy() Proxy {
	y, ok := u.proxy.Load().(Proxy)
	if ok {
		return y
	}
	return &DefaultProxy{}
}

func NewUDPServer(host string, handle func([]byte, Proxy) ([]byte, error)) (Server, error) {
	u := &UDPServer{
		host:   host,
		handle: handle,
		proxy:  atomic.Value{},
	}

	if host == "" {
		return u, nil
	}

	err := u.run()
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (u *UDPServer) SetServer(host string) error {
	if u.host == host {
		return nil
	}

	_ = u.Close()

	u.lock.Lock()
	defer u.lock.Unlock()

	if host == "" {
		return nil
	}

	u.host = host

	fmt.Println("SetServer create new server")
	return u.run()
}

func (u *UDPServer) Close() error {
	if u.listener == nil {
		return nil
	}
	return u.listener.Close()
}

func (u *UDPServer) run() (err error) {
	u.listener, err = net.ListenPacket("udp", u.host)
	if err != nil {
		return fmt.Errorf("UdpServer:run() -> %v", err)
	}

	go func() {
		err := u.process()
		if err != nil {
			log.Println(err)
		}
	}()
	return nil
}

func (u *UDPServer) process() error {
	u.lock.Lock()
	defer u.lock.Unlock()
	fmt.Println("New UDP Server:", u.host)
	var tempDelay time.Duration
	for {
		b := make([]byte, 600)
		n, remoteAddr, err := u.listener.ReadFrom(b)
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
				log.Printf("checked udp server closed: %v\n", err)
			} else {
				log.Printf("udp server accept failed: %v\n", err)
			}
			return fmt.Errorf("udp server accept failed: %v", err)
		}

		tempDelay = 0
		go func() {
			data, err := u.handle(b[:n], u.getProxy())
			if err != nil {
				log.Printf("udp handle failed: %v", err)
				return
			}
			_, err = u.listener.WriteTo(data, remoteAddr)
			if err != nil {
				log.Printf("udp listener write to client failed: %v", err)
			}
		}()
	}
}
