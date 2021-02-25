package proxy

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/net/utils"
)

type UdpServer struct {
	Server
	host        string
	closed      chan bool
	queueClosed chan bool
	handle      func(net.PacketConn, net.Addr, []byte, func(string) (net.PacketConn, error))
	udpConn     func(string) (net.PacketConn, error)
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
	select {
	case <-u.closed:
		fmt.Println("UpdateListen already closed")
	default:
		fmt.Println("UpdateListen close s.closed")
		close(u.closed)
	}

	select {
	case <-u.queueClosed:
		fmt.Println("UpdateListen queue closed")
	}

	if host == "" {
		return nil
	}

	u.host = host

	fmt.Println("UpdateListen create new server")
	return u.run()
}

func (u *UdpServer) SetTCPConn(func(string) (net.Conn, error)) {

}

func (u *UdpServer) Close() error {
	close(u.closed)
	return nil
}

type udpQueueData struct {
	remoteAddr net.Addr
	b          []byte
}

func (u *UdpServer) run() error {
	fmt.Println("New UDP Server:", u.host)
	listener, err := net.ListenPacket("udp", u.host)
	if err != nil {
		return fmt.Errorf("UdpServer:run() -> %v", err)
	}

	u.closed = make(chan bool)

	go func() {
		queue := make(chan udpQueueData, 10)
		u.startQueue(u.host, listener, queue)
		u.processQueue(u.host, listener, queue)
	}()
	return nil
}

func (u *UdpServer) startQueue(host string, listener net.PacketConn, queue chan udpQueueData) {
	go func() {
		u.queueClosed = make(chan bool)
		for {
			b := utils.BuffPool.Get().([]byte)
			n, remoteAddr, err := listener.ReadFrom(b)
			if err != nil {
				select {
				case <-u.closed:
					fmt.Println("Close UDP Queue", host)
					close(u.queueClosed)
					return
				default:
					continue
				}
			}
			queue <- udpQueueData{remoteAddr: remoteAddr, b: b[:n]}
		}
	}()
}
func (u *UdpServer) processQueue(host string, listener net.PacketConn, queue chan udpQueueData) {
	for {
		select {
		case <-u.closed:
			listener.Close()
			fmt.Println("Close UDP Server", host)
			select {
			case <-u.queueClosed:
				fmt.Println("queue already closed, exit function")
			}
			return
		case data := <-queue:
			u.handle(listener, data.remoteAddr, data.b, u.udpConn)
		}
	}
}
