package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

type udpserver struct {
	listener net.PacketConn
	proxy    Proxy
}

type udpOpt struct {
	config     net.ListenConfig
	handle     func([]byte, func(data []byte), Proxy) error
	listenFunc func(net.PacketConn, Proxy) error
}

func UDPWithListenConfig(n net.ListenConfig) func(u *udpOpt) {
	return func(u *udpOpt) {
		u.config = n
	}
}

func UDPWithListenFunc(f func(net.PacketConn, Proxy) error) func(u *udpOpt) {
	return func(u *udpOpt) {
		u.listenFunc = f
	}
}

func UDPWithHandle(f func([]byte, func([]byte), Proxy) error) func(u *udpOpt) {
	return func(u *udpOpt) {
		u.handle = f
	}
}

func NewUDPServer(host string, proxy Proxy, opt ...func(u *udpOpt)) (Server, error) {
	if host == "" {
		return nil, fmt.Errorf("host not defined")
	}

	if proxy == nil {
		proxy = &Default{}
	}
	udp := &udpserver{proxy: proxy}
	u := &udpOpt{config: net.ListenConfig{}}
	for i := range opt {
		opt[i](u)
	}

	if u.listenFunc == nil && u.handle == nil {
		return nil, fmt.Errorf("udp server must define listen func or handle func")
	}

	if u.listenFunc == nil && u.handle != nil {
		u.listenFunc = func(pc net.PacketConn, p Proxy) error { return udp.defaultListenFunc(pc, u.handle) }
	}

	err := udp.run(host, u.config, u.listenFunc)
	if err != nil {
		return nil, fmt.Errorf("udp server run failed: %v", err)
	}
	return udp, nil
}

func (u *udpserver) Close() error {
	if u.listener == nil {
		return nil
	}
	return u.listener.Close()
}

func (u *udpserver) run(host string, config net.ListenConfig, listenFunc func(net.PacketConn, Proxy) error) (err error) {
	u.listener, err = config.ListenPacket(context.TODO(), "udp", host)
	if err != nil {
		return fmt.Errorf("udp server listen failed: %v", err)
	}

	log.Println("new udp listener:", host)
	go func() {
		err := listenFunc(u.listener, u)
		if err != nil {
			log.Println(err)
		}
	}()
	return nil
}

func (t *udpserver) Conn(host string) (net.Conn, error) {
	return t.proxy.Conn(host)
}

func (t *udpserver) PacketConn(host string) (net.PacketConn, error) {
	if t.listener.LocalAddr().String() == host {
		return nil, fmt.Errorf("access host same as listener: %v", t.listener.LocalAddr())
	}
	return t.proxy.PacketConn(host)
}

func (u *udpserver) defaultListenFunc(l net.PacketConn, handle func([]byte, func(data []byte), Proxy) error) error {
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
			err = handle(b, func(data []byte) {
				_, err = l.WriteTo(data, remoteAddr)
				if err != nil {
					log.Printf("udp listener write to client failed: %v", err)
				}
			}, u)
			if err != nil {
				log.Printf("udp handle failed: %v", err)
				return
			}
		}(b[:n], remoteAddr)
	}
}
