package proxy

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
)

type UdpServer struct {
	Server
	host     string
	lock     sync.Mutex
	connLock sync.RWMutex
	listener net.PacketConn
	handle   func([]byte, func(string) (net.PacketConn, error)) ([]byte, error)
	udpConn  func(string) (net.PacketConn, error)
}

func (u *UdpServer) SetUDPConn(f func(string) (net.PacketConn, error)) {
	u.connLock.Lock()
	defer u.connLock.Unlock()
	u.udpConn = f
}

func (u *UdpServer) getUDPConn() func(string) (net.PacketConn, error) {
	u.connLock.RLock()
	defer u.connLock.RUnlock()
	return u.udpConn
}

func NewUDPServer(host string, handle func([]byte, func(string) (net.PacketConn, error)) ([]byte, error)) (UDPServer, error) {
	u := &UdpServer{
		host:   host,
		handle: handle,
		udpConn: func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		},
	}

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

func (u *UdpServer) process() {
	u.lock.Lock()
	defer u.lock.Unlock()
	for {
		b := make([]byte, 600)
		n, remoteAddr, err := u.listener.ReadFrom(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("checked close")
				return
			}
			log.Println(err)
			continue
		}

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
