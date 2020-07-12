package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// Server <--
type TCPServer struct {
	Server
	host    string
	tcpConn func(string) (net.Conn, error)
	ctx     context.Context
	cancel  context.CancelFunc
	handle  func(net.Conn, func(string) (net.Conn, error))
}

type Option struct {
	TcpConn func(string) (net.Conn, error)
}

// NewTCPServer create new TCP listener
func NewTCPServer(host string, handle func(net.Conn, func(string) (net.Conn, error)), modeOption ...func(*Option)) (Server, error) {
	if host == "" {
		return nil, errors.New("host empty")
	}
	if handle == nil {
		return nil, errors.New("handle is must")
	}
	o := &Option{
		TcpConn: func(s string) (net.Conn, error) {
			return net.Dial("tcp", s)
		},
	}
	for index := range modeOption {
		if modeOption[index] == nil {
			continue
		}
		modeOption[index](o)
	}

	s := &TCPServer{
		host:    host,
		handle:  handle,
		tcpConn: o.TcpConn,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	err := s.run(s.ctx)
	if err != nil {
		return nil, fmt.Errorf("server Run -> %v", err)
	}
	return s, nil
}

func (s *TCPServer) UpdateListen(host string) (err error) {
	if s.ctx == nil {
		goto _creatServer
	}
	select {
	case <-s.ctx.Done():
		goto _creatServer
	default:
		if s.host == host {
			return
		}
		s.cancel()
	}
_creatServer:
	if host == "" {
		return
	}
	s.host = host
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s.run(s.ctx)
}

func (s *TCPServer) SetTCPConn(conn func(string) (net.Conn, error)) {
	if conn == nil {
		return
	}
	s.tcpConn = conn
}

func (s *TCPServer) GetListenHost() string {
	return s.host
}

// Socks5 <--
func (s *TCPServer) run(ctx context.Context) (err error) {
	fmt.Println("New TCP Server:", s.host)
	listener, err := net.Listen("tcp", s.host)
	if err != nil {
		return fmt.Errorf("Socks5:Listen -> %v", err)
	}
	go func(ctx context.Context) {
		queue := make(chan net.Conn, 10)
		ctxListen, cancel := context.WithCancel(context.Background())
		go func(ctx context.Context) {
			for {
				client, err := listener.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						fmt.Println("Close Queue")
						return
					default:
						continue
					}
				}
				queue <- client
			}
		}(ctxListen)
		for {
			select {
			case <-ctx.Done():
				cancel()
				_ = listener.Close()
				fmt.Println("Close Server")
				return
			case client := <-queue:
				go func() {
					_ = client.(*net.TCPConn).SetKeepAlive(true)
					defer client.Close()
					s.handle(client, s.tcpConn)
				}()
			}
		}
	}(ctx)
	return
}

func (s *TCPServer) Close() error {
	s.cancel()
	return nil
}

func (s *TCPServer) defaultHandle(conn net.Conn) {
	conn.Close()
}
