package proxy

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// TcpServer tcp server common
type TcpServer struct {
	Server
	host string
	lock sync.Mutex

	listener net.Listener
	tcpConn  func(string) (net.Conn, error)
	handle   func(net.Conn, func(string) (net.Conn, error))
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
	_ = t.Close()

	t.lock.Lock()
	defer t.lock.Unlock()

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

func (t *TcpServer) run() (err error) {
	fmt.Println("New TCP Server:", t.host)
	t.listener, err = net.Listen("tcp", t.host)
	if err != nil {
		return fmt.Errorf("TcpServer:run() -> %v", err)
	}

	go t.process()
	return
}

func (t *TcpServer) process() {
	t.lock.Lock()
	defer t.lock.Unlock()
	for {
		c, err := t.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("checked close")
				return
			}
			log.Println(err)
			continue
		}
		go func() {
			defer c.Close()
			t.handle(c, t.tcpConn)
		}()
	}
}

func (t *TcpServer) Close() error {
	return t.listener.Close()
}

func (t *TcpServer) defaultHandle(conn net.Conn) {
	conn.Close()
}
