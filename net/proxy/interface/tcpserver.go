package proxy

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// TcpServer tcp server common
type TcpServer struct {
	Server
	host        string
	closed      chan bool
	queueClosed chan bool
	tcpConn     func(string) (net.Conn, error)
	handle      func(net.Conn, func(string) (net.Conn, error))
}

type Option struct {
	TcpConn func(string) (net.Conn, error)
}

// NewTCPServer create new TCP listener
func NewTCPServer(host string, handle func(net.Conn, func(string) (net.Conn, error)), modeOption ...func(*Option)) (TCPServer, error) {
	if host == "" {
		return nil, errors.New("host empty")
	}
	if handle == nil {
		return nil, errors.New("handle is must")
	}
	o := &Option{
		TcpConn: func(s string) (net.Conn, error) {
			return net.DialTimeout("tcp", s, 20*time.Second)
		},
	}
	for index := range modeOption {
		if modeOption[index] == nil {
			continue
		}
		modeOption[index](o)
	}

	s := &TcpServer{
		host:    host,
		handle:  handle,
		tcpConn: o.TcpConn,
	}
	err := s.run()
	if err != nil {
		return nil, fmt.Errorf("server Run -> %v", err)
	}
	return s, nil
}

func (t *TcpServer) UpdateListen(host string) (err error) {
	if t.host == host {
		return
	}
	select {
	case <-t.closed:
		fmt.Println("UpdateListen already closed")
	default:
		fmt.Println("UpdateListen close s.closed")
		close(t.closed)
	}

	select {
	case <-t.queueClosed:
		fmt.Println("UpdateListen queue closed")
	}

	if host == "" {
		return
	}

	t.host = host

	fmt.Println("UpdateListen create new server")
	return t.run()
}

func (t *TcpServer) SetTCPConn(conn func(string) (net.Conn, error)) {
	if conn == nil {
		return
	}
	t.tcpConn = conn
}

func (t *TcpServer) GetListenHost() string {
	return t.host
}

// Socks5 <--
func (t *TcpServer) run() (err error) {
	fmt.Println("New TCP Server:", t.host)
	listener, err := net.Listen("tcp", t.host)
	if err != nil {
		return fmt.Errorf("TcpServer:run() -> %v", err)
	}

	t.closed = make(chan bool)

	go func() {
		queue := make(chan net.Conn, 10)
		defer close(queue)
		t.startQueue(t.host, listener, queue)
		t.processQueue(t.host, listener, queue)
	}()
	return
}

func (t *TcpServer) startQueue(host string, listener net.Listener, queue chan net.Conn) {
	go func() {
		t.queueClosed = make(chan bool)
		for {
			client, err := listener.Accept()
			if err != nil {
				select {
				case <-t.closed:
					fmt.Println("Close TCP Queue", host)
					close(t.queueClosed)
					return
				default:
					continue
				}
			}
			queue <- client
		}
	}()
}

func (t *TcpServer) processQueue(host string, listener net.Listener, queue chan net.Conn) {
	for {
		select {
		case <-t.closed:
			_ = listener.Close()
			fmt.Println("Close TCP Server", host)
			select {
			case <-t.queueClosed:
				fmt.Println("client queue already closed, exit function")
			}
			return
		case client := <-queue:
			go func() {
				if x, ok := client.(*net.TCPConn); ok {
					x.SetKeepAlive(true)
				}
				defer client.Close()
				t.handle(client, t.tcpConn)
			}()
		}
	}
}

func (t *TcpServer) Close() error {
	close(t.closed)
	return nil
}

func (t *TcpServer) defaultHandle(conn net.Conn) {
	conn.Close()
}
