package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

// tcpserver tcp server common
type tcpserver struct {
	listener net.Listener
	proxy    Proxy
}

type tcpOpt struct {
	config net.ListenConfig
	handle func(net.Conn, Proxy)
}

func TCPWithListenConfig(n net.ListenConfig) func(u *tcpOpt) {
	return func(u *tcpOpt) {
		u.config = n
	}
}

func TCPWithHandle(f func(net.Conn, Proxy)) func(u *tcpOpt) {
	return func(u *tcpOpt) {
		u.handle = f
	}
}

// NewTCPServer create new TCP listener
func NewTCPServer(host string, proxy Proxy, opt ...func(*tcpOpt)) (Server, error) {
	if host == "" {
		return nil, fmt.Errorf("host is empty")
	}

	if proxy == nil {
		proxy = &Default{}
	}

	s := &tcpOpt{config: net.ListenConfig{}}

	for i := range opt {
		opt[i](s)
	}

	if s.handle == nil {
		return nil, fmt.Errorf("handle is nil")
	}

	tcp := &tcpserver{proxy: proxy}
	err := tcp.run(host, s.config, s.handle)
	if err != nil {
		return nil, fmt.Errorf("tcp server run failed: %v", err)
	}
	return tcp, nil
}

func (t *tcpserver) Conn(host string) (net.Conn, error) {
	if t.listener.Addr().String() == host {
		return nil, fmt.Errorf("access host same as listener: %v", t.listener.Addr())
	}
	return t.proxy.Conn(host)
}

func (t *tcpserver) PacketConn(host string) (net.PacketConn, error) {
	return t.proxy.PacketConn(host)
}

func (t *tcpserver) run(host string, config net.ListenConfig, handle func(net.Conn, Proxy)) (err error) {
	t.listener, err = config.Listen(context.TODO(), "tcp", host)
	if err != nil {
		return fmt.Errorf("tcp server listen failed: %v", err)
	}

	log.Println("new tcp listener:", host)

	go func() {
		err := t.process(handle)
		if err != nil {
			log.Println(err)
		}
	}()
	return
}

func (t *tcpserver) process(handle func(net.Conn, Proxy)) error {
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

				if max := 5 * time.Second; tempDelay > max {
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
			handle(c, t)
		}()
	}
}

func (t *tcpserver) Close() error {
	if t.listener == nil {
		return nil
	}
	return t.listener.Close()
}
