package proxy

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/net/utils"
)

type UdpServer struct {
	Server
	host     string
	lock     sync.Mutex
	listener net.PacketConn
	handle   func(net.PacketConn, net.Addr, []byte, func(string) (net.PacketConn, error))
	udpConn  func(string) (net.PacketConn, error)
}

func (u *UdpServer) SetUDPConn(f func(string) (net.PacketConn, error)) {
	u.udpConn = f
}

func NewUDPServer(host string, handle func(from net.PacketConn, remoteAddr net.Addr, data []byte, udpConn func(string) (net.PacketConn, error))) (UDPServer, error) {
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
		b := utils.BuffPool.Get().([]byte)
		n, remoteAddr, err := u.listener.ReadFrom(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("checked close")
				return
			}
			log.Println(err)
			continue
		}

		go u.handle(u.listener, remoteAddr, b[:n], u.udpConn)
	}
}
