package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
)

type UDPServer struct {
	host   string
	lock   sync.Mutex
	config net.ListenConfig

	listener   net.PacketConn
	handle     func([]byte, func(data []byte), Proxy) error
	listenFunc func(net.PacketConn, Proxy) error
	proxy      atomic.Value
}

func (u *UDPServer) SetProxy(f Proxy) {
	if f == nil {
		f = &Default{}
	}
	u.proxy.Store(f)
}

func (u *UDPServer) getProxy() Proxy {
	y, ok := u.proxy.Load().(Proxy)
	if ok {
		return y
	}
	return &Default{}
}

func UDPWithListenConfig(n net.ListenConfig) func(u *UDPServer) {
	return func(u *UDPServer) {
		u.config = n
	}
}

func UDPWithListenFunc(f func(net.PacketConn, Proxy) error) func(u *UDPServer) {
	return func(u *UDPServer) {
		u.listenFunc = f
	}
}

func UDPWithHandle(f func([]byte, func([]byte), Proxy) error) func(u *UDPServer) {
	return func(u *UDPServer) {
		u.handle = f
	}
}

func NewUDPServer(host string, opt ...func(u *UDPServer)) (Server, error) {
	u := &UDPServer{
		host:   host,
		handle: func(b []byte, rw func([]byte), p Proxy) error { return fmt.Errorf("handle not defined") },
		proxy:  atomic.Value{},
		config: net.ListenConfig{},
	}
	u.listenFunc = func(pc net.PacketConn, p Proxy) error { return u.defaultListenFunc(pc) }

	for i := range opt {
		opt[i](u)
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

	u.host = host

	if host == "" {
		return nil
	}

	logasfmt.Println("SetServer create new server")
	return u.run()
}

func (u *UDPServer) Close() error {
	if u.listener == nil {
		return nil
	}
	return u.listener.Close()
}

func (u *UDPServer) run() (err error) {
	u.listener, err = u.config.ListenPacket(context.TODO(), "udp", u.host)
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

func (t *UDPServer) Conn(host string) (net.Conn, error) {
	return t.getProxy().Conn(host)
}

func (t *UDPServer) PacketConn(host string) (net.PacketConn, error) {
	if t.listener.LocalAddr().String() == host {
		return nil, fmt.Errorf("access host same as listener: %v", t.listener.LocalAddr())
	}
	return t.getProxy().PacketConn(host)
}

func (u *UDPServer) process() error {
	u.lock.Lock()
	defer u.lock.Unlock()
	logasfmt.Println("New UDP Server:", u.host)
	return u.listenFunc(u.listener, u)
}

func (u *UDPServer) defaultListenFunc(l net.PacketConn) error {
	var tempDelay time.Duration
	for {
		b := make([]byte, 1024)
		n, remoteAddr, err := l.ReadFrom(b)
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

		go func(b []byte, remoteAddr net.Addr) {
			err = u.handle(b, func(data []byte) {
				_, err = l.WriteTo(data, remoteAddr)
				if err != nil {
					log.Printf("udp listener write to client failed: %v", err)
				}
			}, u)
			if err != nil {
				log.Printf("udp handle failed: %v", err)
				return
				// continue
			}
		}(b[:n], remoteAddr)
	}
}
