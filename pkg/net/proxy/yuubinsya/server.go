package yuubinsya

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	quicgo "github.com/quic-go/quic-go"
)

type yuubinsya struct {
	Config
	Listener   net.Listener
	handshaker handshaker
	handler    netapi.Handler
}

type Type int

var (
	RAW_TCP   Type = 1
	TLS       Type = 2
	QUIC      Type = 3
	WEBSOCKET Type = 4
	GRPC      Type = 5
	HTTP2     Type = 6
	REALITY   Type = 7
)

type Config struct {
	Handler             netapi.Handler
	Host                string
	Password            []byte
	TlsConfig           *tls.Config
	Type                Type
	ForceDisableEncrypt bool

	NewListener func(net.Listener) (net.Listener, error)
}

func (c Config) String() string {
	return fmt.Sprintf(`
	{
		"host": "%s",
		"password": "%s",
		"type": %d,
	}
	`, c.Host, c.Password, c.Type)
}

func NewServer(config Config) *yuubinsya {
	return &yuubinsya{
		Config:     config,
		handler:    config.Handler,
		handshaker: NewHandshaker(!config.ForceDisableEncrypt && config.TlsConfig == nil, config.Password),
	}
}

type listener struct {
	net.Listener
	closer []io.Closer
}

func (l *listener) Close() error {
	for _, v := range l.closer {
		v.Close()
	}

	return l.Listener.Close()
}

func (y *yuubinsya) Server() (net.Listener, error) {
	if y.Type == QUIC {
		packetConn, err := dialer.ListenPacket("udp", y.Host)
		if err != nil {
			return nil, err
		}
		quicListener, err := quic.NewServer(packetConn, y.TlsConfig, y.handler)
		if err != nil {
			packetConn.Close()
			return nil, err
		}

		return &listener{quicListener, []io.Closer{packetConn}}, nil
	}

	tcpListener, err := dialer.ListenContext(context.TODO(), "tcp", y.Host)
	if err != nil {
		return nil, err
	}

	if y.TlsConfig != nil {
		tcpListener = tls.NewListener(tcpListener, y.TlsConfig)
	}

	if y.NewListener != nil {
		tcpListener, err = y.NewListener(tcpListener)
	}

	return tcpListener, err
}

func (y *yuubinsya) Start() (err error) {
	if y.Listener, err = y.Server(); err != nil {
		return
	}
	defer y.Listener.Close()

	log.Info("new yuubinsya server", "type", y.Type, "host", y.Listener.Addr())

	for {
		conn, err := y.Listener.Accept()
		if err != nil {
			log.Error("accept failed", "err", err)

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}

		if c, ok := conn.(interface{ SetKeepAlive(bool) error }); ok {
			_ = c.SetKeepAlive(true)
		}

		go func() {
			if err := y.handle(conn); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Error("handle failed", slog.Any("from", conn.RemoteAddr()), slog.Any("err", err))
			}
		}()
	}
}

type Net byte

var (
	TCP Net = 66
	UDP Net = 77
)

func (n Net) Unknown() bool { return n != TCP && n != UDP }

func (y *yuubinsya) handle(conn net.Conn) error {
	c, err := y.handshaker.handshakeServer(conn)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	net, err := y.handshaker.parseHeader(c)
	if err != nil {
		write403(conn)
		return fmt.Errorf("parse header failed: %w", err)
	}

	switch net {
	case TCP:
		target, err := s5c.ResolveAddr(c)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}

		addr := target.Address(statistic.Type_tcp)

		log.Debug("new tcp connect", "from", c.RemoteAddr(), "to", addr)

		y.handler.Stream(context.TODO(), &netapi.StreamMeta{
			Source:      c.RemoteAddr(),
			Destination: addr,
			Inbound:     c.LocalAddr(),
			Src:         c,
			Address:     addr,
		})
	case UDP:
		return func() error {
			defer c.Close()
			log.Debug("new udp connect", "from", c.RemoteAddr())
			for {
				if err := y.forwardPacket(c); err != nil {
					return fmt.Errorf("handle packet request failed: %w", err)
				}
			}
		}()
	}

	return nil
}

func (y *yuubinsya) Close() error {
	if y.Listener == nil {
		return nil
	}
	return y.Listener.Close()
}

func (y *yuubinsya) forwardPacket(c net.Conn) error {
	addr, err := s5c.ResolveAddr(c)
	if err != nil {
		return err
	}

	var length uint16
	if err := binary.Read(c, binary.BigEndian, &length); err != nil {
		return err
	}

	bufv2 := pool.GetBytesV2(length)

	if _, err = io.ReadFull(c, bufv2.Bytes()); err != nil {
		return err
	}

	src := c.RemoteAddr()
	if conn, ok := c.(interface{ StreamID() quicgo.StreamID }); ok {
		src = &quic.QuicAddr{Addr: c.RemoteAddr(), ID: conn.StreamID()}
	}

	y.Config.Handler.Packet(
		context.TODO(),
		&netapi.Packet{
			Src:     src,
			Dst:     addr.Address(statistic.Type_udp),
			Payload: bufv2.Bytes(),
			WriteBack: func(buf []byte, from net.Addr) (int, error) {
				defer pool.PutBytesV2(bufv2)

				addr, err := netapi.ParseSysAddr(from)
				if err != nil {
					return 0, err
				}

				s5Addr := s5c.ParseAddr(addr)

				buffer := pool.GetBytesV2(len(s5Addr) + 2 + nat.MaxSegmentSize)
				defer pool.PutBytesV2(buffer)

				copy(buffer.Bytes(), s5Addr)
				binary.BigEndian.PutUint16(buffer.Bytes()[len(s5Addr):], uint16(len(buf)))
				copy(buffer.Bytes()[len(s5Addr)+2:], buf)

				if _, err := c.Write(buffer.Bytes()[:len(s5Addr)+2+len(buf)]); err != nil {
					return 0, err
				}

				return len(buf), nil
			},
		})
	return nil
}

func write403(conn net.Conn) {
	data := []byte(`<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty</center>
</body>
</html>`)
	t := http.Response{
		Status:        http.StatusText(http.StatusForbidden),
		StatusCode:    http.StatusForbidden,
		Body:          io.NopCloser(bytes.NewBuffer(data)),
		Header:        http.Header{},
		Proto:         "HTTP/2",
		ProtoMajor:    2,
		ProtoMinor:    2,
		ContentLength: int64(len(data)),
	}

	t.Header.Add("content-type", "text/html")
	t.Header.Add("date", time.Now().UTC().Format(time.RFC1123))
	t.Header.Add("server", "openresty")

	_ = t.Write(conn)
}
