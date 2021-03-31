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

type UdpServer struct {
	Server
	host string
	lock sync.Mutex

	listener net.PacketConn
	handle   func([]byte, func(string) (net.PacketConn, error)) ([]byte, error)
	udpConn  atomic.Value
}

func (u *UdpServer) SetUDPConn(f func(string) (net.PacketConn, error)) {
	if f == nil {
		return
	}
	u.udpConn.Store(f)
}

func (u *UdpServer) getUDPConn() func(string) (net.PacketConn, error) {
	y, ok := u.udpConn.Load().(func(string) (net.PacketConn, error))
	if ok {
		return y
	}
	return func(s string) (net.PacketConn, error) {
		return net.ListenPacket("udp", "")
	}
}

func NewUDPServer(host string, handle func([]byte, func(string) (net.PacketConn, error)) ([]byte, error)) (UDPServer, error) {
	u := &UdpServer{
		host:    host,
		handle:  handle,
		udpConn: atomic.Value{},
	}
	u.udpConn.Store(
		func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		},
	)

	err := u.run()
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (u *UdpServer) UpdateListen(host string) error {
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

	fmt.Println("UpdateListen create new server")
	return u.run()
}

func (u *UdpServer) Close() error {
	if u.listener == nil {
		return nil
	}
	return u.listener.Close()
}

func (u *UdpServer) run() (err error) {
	fmt.Println("New UDP Server:", u.host)
	u.listener, err = net.ListenPacket("udp", u.host)
	if err != nil {
		return fmt.Errorf("UdpServer:run() -> %v", err)
	}

	go u.process()
	return nil
}

func (u *UdpServer) process() error {
	u.lock.Lock()
	defer u.lock.Unlock()
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
			data, err := u.handle(b[:n], u.getUDPConn())
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
