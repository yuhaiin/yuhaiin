package proxy

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/net/common"
)

type UdpServer struct {
	Server
	host     string
	handle   func(*net.UDPConn, net.Addr, []byte, func(string) (*net.UDPConn, error))
	udpConn  func(string) (*net.UDPConn, error)
	ctx      context.Context
	cancel   context.CancelFunc
	ctxQueue context.Context
}

func (u *UdpServer) SetUDPConn(f func(string) (*net.UDPConn, error)) {
	u.udpConn = f
}

func NewUDPServer(host string, handle func(from *net.UDPConn, remoteAddr net.Addr, data []byte, udpConn func(string) (*net.UDPConn, error))) (UDPServer, error) {
	udpConn := func(host string) (*net.UDPConn, error) {
		// make a writer and write to dst
		//targetUDPAddr, err := net.ResolveUDPAddr("udp", host)
		//if err != nil {
		//	return nil, err
		//}
		target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, err
		}
		return target, nil
	}
	u := &UdpServer{
		host:    host,
		handle:  handle,
		udpConn: udpConn,
	}
	u.ctx, u.cancel = context.WithCancel(context.Background())
	err := u.run(u.ctx)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (u *UdpServer) UpdateListen(host string) error {
	if u.ctx == nil {
		goto _creatServer
	}

	select {
	case <-u.ctx.Done():
		goto _creatServer
	default:
		if u.host == host {
			return nil
		}
		u.cancel()
		if u.ctxQueue == nil {
			break
		}
		select {
		case <-u.ctxQueue.Done():
		}
	}

_creatServer:
	if host == "" {
		return nil
	}
	u.host = host
	u.ctx, u.cancel = context.WithCancel(context.Background())
	return u.run(u.ctx)
}

func (u *UdpServer) SetTCPConn(func(string) (net.Conn, error)) {

}

func (u *UdpServer) Close() error {
	return nil
}

func (u *UdpServer) run(ctx context.Context) error {
	localAddr, err := net.ResolveUDPAddr("udp", u.host)
	if err != nil {
		log.Printf("UDP server address error: %s\n", err.Error())
		return fmt.Errorf("UpdateUDPListenAddr:ResolveUDPAddr -> %v", err)
	}
	fmt.Println("New UDP Server:", u.host)
	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("UdpServer:run() -> %v", err)
	}
	go func(ctx context.Context) {
		queue := make(chan struct {
			remoteAddr net.Addr
			b          []byte
		}, 10)
		var cancel context.CancelFunc
		u.ctxQueue, cancel = context.WithCancel(context.Background())
		go func(ctx context.Context) {
			for {
				b := common.BuffPool.Get().([]byte)
				n, remoteAddr, err := listener.ReadFromUDP(b)
				if err != nil {
					select {
					case <-ctx.Done():
						fmt.Println("Close UDP Queue", u.host)
						return
					default:
						continue
					}
				}
				queue <- struct {
					remoteAddr net.Addr
					b          []byte
				}{remoteAddr: remoteAddr, b: b[:n]}
			}
		}(u.ctxQueue)
		for {
			select {
			case <-ctx.Done():
				cancel()
				listener.Close()
				fmt.Println("Close UDP Server", u.host)
				return
			case data := <-queue:
				u.handle(listener, data.remoteAddr, data.b, u.udpConn)
			}
		}
	}(ctx)
	return nil
}
