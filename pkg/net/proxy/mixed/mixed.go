package mixed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	httpproxy "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	s5s "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type Mixed struct {
	lis net.Listener

	httpserver    netapi.Server
	socks5server  netapi.Server
	socks4aserver netapi.Server
}

func NewServer(o *listener.Opts[*listener.Protocol_Mix]) (netapi.Server, error) {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", o.Protocol.Mix.Host)
	if err != nil {
		return nil, fmt.Errorf("new listener failed: %w", err)
	}

	socksCL := newChanListener(lis)
	httpCL := newChanListener(lis)
	socks4aCL := newChanListener(lis)

	ss, err := s5s.NewServerWithListener(socksCL,
		listener.CovertOpts(o, func(l *listener.Protocol_Mix) *listener.Protocol_Socks5 { return l.SOCKS5() }))
	if err != nil {
		lis.Close()
		socksCL.Close()
		httpCL.Close()
		socks4aCL.Close()
		return nil, err
	}

	hs := httpproxy.NewServerWithListener(httpCL,
		listener.CovertOpts(o, func(l *listener.Protocol_Mix) *listener.Protocol_Http { return l.HTTP() }))

	socks4a := socks4a.NewServerWithListener(socks4aCL,
		listener.CovertOpts(o, func(l *listener.Protocol_Mix) *listener.Protocol_Socks4A { return l.SOCKS4A() }))

	m := &Mixed{lis, hs, ss, socks4a}

	go func() {
		if err := m.handle(socksCL, socks4aCL, httpCL); err != nil {
			log.Debug("mixed handle failed", "err", err)
		}
	}()

	return m, nil
}

func (m *Mixed) Close() error {
	var err error
	if er := m.lis.Close(); er != nil {
		err = errors.Join(err, er)
	}
	if er := m.httpserver.Close(); er != nil {
		err = errors.Join(err, er)
	}
	if er := m.socks5server.Close(); er != nil {
		err = errors.Join(err, er)
	}

	return err
}

func (m *Mixed) handle(socks5, socks4a, http *chanListener) error {
	defer socks5.Close()
	defer socks4a.Close()
	defer http.Close()

	for {
		conn, err := m.lis.Accept()
		if err != nil {
			log.Error("mixed accept failed", "err", err)

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}

		protocol := make([]byte, 1)
		if _, err := io.ReadFull(conn, protocol); err != nil {
			conn.Close()
			continue
		}

		conn = &mixedConn{protocol[0], conn}

		switch protocol[0] {
		case 0x05:
			socks5.NewConn(conn)
		case 0x04:
			socks4a.NewConn(conn)
		default:
			http.NewConn(conn)
		}
	}
}

type chanListener struct {
	mu     sync.Mutex
	closed bool
	net.Listener
	channel chan net.Conn
}

func newChanListener(lis net.Listener) *chanListener {
	return &chanListener{
		Listener: lis,
		channel:  make(chan net.Conn)}
}

func (c *chanListener) Accept() (net.Conn, error) {
	conn, ok := <-c.channel
	if !ok {
		return nil, net.ErrClosed
	}

	return conn, nil
}

func (c *chanListener) NewConn(conn net.Conn) { c.channel <- conn }

func (c *chanListener) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.channel)
	return c.Listener.Close()
}

type mixedConn struct {
	protocol byte
	net.Conn
}

func (r *mixedConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	if r.protocol != 0 {
		b[0] = r.protocol
		n, err := r.Conn.Read(b[1:])
		r.protocol = 0
		return n + 1, err
	}

	return r.Conn.Read(b)
}
