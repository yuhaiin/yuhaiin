package mixed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

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

	http      *httpproxy.HandleServer
	socks5    *s5s.Socks5
	socks5UDP net.PacketConn
	socks4a   *socks4a.Server
}

func optToHTTP(o *listener.Opts[*listener.Protocol_Mix]) *listener.Opts[*listener.Protocol_Http] {
	return listener.CovertOpts(o, func(l *listener.Protocol_Mix) *listener.Protocol_Http { return l.HTTP() })
}

func optToSocks5(o *listener.Opts[*listener.Protocol_Mix]) *listener.Opts[*listener.Protocol_Socks5] {
	return listener.CovertOpts(o, func(l *listener.Protocol_Mix) *listener.Protocol_Socks5 { return l.SOCKS5() })
}

func optToSocks4A(o *listener.Opts[*listener.Protocol_Mix]) *listener.Opts[*listener.Protocol_Socks4A] {
	return listener.CovertOpts(o, func(l *listener.Protocol_Mix) *listener.Protocol_Socks4A { return l.SOCKS4A() })
}

func NewServer(o *listener.Opts[*listener.Protocol_Mix]) (netapi.Server, error) {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", o.Protocol.Mix.Host)
	if err != nil {
		return nil, fmt.Errorf("new listener failed: %w", err)
	}

	s5UDP, err := s5s.NewUDPServer(o.Protocol.Mix.Host, o.Handler)
	if err != nil {
		return nil, err
	}

	m := &Mixed{
		lis,
		httpproxy.NewServerHandler(optToHTTP(o), lis.Addr()),
		s5s.NewServerHandler(optToSocks5(o), true),
		s5UDP,
		socks4a.NewServerHandler(optToSocks4A(o)),
	}

	go func() {
		if err := m.handle(); err != nil {
			log.Debug("mixed handle failed", "err", err)
		}
	}()

	return m, nil
}

func (m *Mixed) Close() error {
	if m.http != nil {
		_ = m.http.Close()
	}
	if m.socks5UDP != nil {
		_ = m.socks5UDP.Close()
	}

	return m.lis.Close()
}

func (m *Mixed) handle() error {
	for {
		conn, err := m.lis.Accept()
		if err != nil {
			log.Error("mixed accept failed", "err", err)

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}

		go func() {
			protocol := make([]byte, 1)
			if _, err := io.ReadFull(conn, protocol); err != nil {
				conn.Close()
				return
			}

			conn = newMultipleReaderConn(conn, io.MultiReader(&net.Buffers{protocol}, conn))

			switch protocol[0] {
			case 0x05:
				err = m.socks5.Handle(conn)
			case 0x04:
				err = m.socks4a.Handle(conn)
			default:
				err = m.http.Handle(conn)
			}

			if err != nil {
				if errors.Is(err, netapi.ErrBlocked) {
					log.Debug(err.Error())
				} else {
					log.Error("mixed handle failed", "err", err)
				}
			}
		}()
	}
}

type multipleReaderConn struct {
	net.Conn
	mr io.Reader
}

func newMultipleReaderConn(c net.Conn, r io.Reader) *multipleReaderConn {
	return &multipleReaderConn{c, r}
}

func (m *multipleReaderConn) Read(b []byte) (int, error) {
	return m.mr.Read(b)
}
