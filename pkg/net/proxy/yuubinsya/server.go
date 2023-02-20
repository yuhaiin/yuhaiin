package yuubinsya

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	quicgo "github.com/quic-go/quic-go"
)

type yuubinsya struct {
	Config

	Lis net.Listener

	handshaker handshaker

	nat *nat.Table
}

type Type int

var (
	RAW_TCP   Type = 1
	TLS       Type = 2
	QUIC      Type = 3
	WEBSOCKET Type = 4
	GRPC      Type = 5
)

type Config struct {
	Dialer              proxy.Proxy
	Host                string
	Password            []byte
	TlsConfig           *tls.Config
	Type                Type
	ForceDisableEncrypt bool
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
		handshaker: NewHandshaker(!config.ForceDisableEncrypt && config.TlsConfig == nil, config.Password),
		nat:        nat.NewTable(config.Dialer),
	}
}

func (y *yuubinsya) Start() error {
	var lis net.Listener
	var err error

	if y.Type != QUIC {
		lis, err = dialer.ListenContext(context.TODO(), "tcp", y.Host)
		if err != nil {
			return err
		}

		if y.TlsConfig != nil {
			lis = tls.NewListener(lis, y.TlsConfig)
		}

		switch y.Type {
		case WEBSOCKET:
			lis = websocket.NewServer(lis)
		case GRPC:
			lis = grpc.NewGrpc(lis)
		}

		defer lis.Close()
	} else {
		packetConn, err := dialer.ListenPacket("udp", y.Host)
		if err != nil {
			return err
		}
		defer packetConn.Close()
		lis, err = quic.NewServer(packetConn, y.TlsConfig)
		if err != nil {
			return err
		}
		defer lis.Close()
	}

	y.Lis = lis
	log.Infoln(y.Type, "new server listen at:", lis.Addr())

	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Errorln("accept failed:", err)
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}

		if c, ok := conn.(interface{ SetKeepAlive(bool) error }); ok {
			c.SetKeepAlive(true)
		}

		go func() {
			defer conn.Close()
			if err := y.handle(conn); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Errorln("handle failed:", err)
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

	z := make([]byte, 2)
	if _, err := io.ReadFull(c, z); err != nil {
		return fmt.Errorf("read net type failed: %w", err)
	}
	net, passwordLen := Net(z[0]), z[1]

	if net.Unknown() {
		write403(conn)
		return fmt.Errorf("unknown network")
	}

	if y.TlsConfig != nil && passwordLen <= 0 {
		write403(conn)
		return fmt.Errorf("password is empty")
	}

	if passwordLen > 0 {
		password := pool.GetBytesV2(passwordLen)
		defer pool.PutBytesV2(password)

		if _, err := io.ReadFull(c, password.Bytes()); err != nil {
			write403(conn)
			return fmt.Errorf("read password failed: %w", err)
		}

		if !bytes.Equal(password.Bytes(), y.Password) {
			write403(conn)
			return errors.New("password is incorrect")
		}
	}

	switch net {
	case TCP:
		return y.stream(c)
	case UDP:
		return y.packet(c)
	}

	return nil
}

func (y *yuubinsya) Close() error {
	if y.Lis == nil {
		return nil
	}
	return y.Lis.Close()
}

func (y *yuubinsya) stream(c net.Conn) error {
	target, err := s5c.ResolveAddr(c)
	if err != nil {
		return fmt.Errorf("resolve addr failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()
	addr := target.Address(statistic.Type_tcp)
	addr.WithValue(proxy.SourceKey{}, c.RemoteAddr())
	addr.WithValue(proxy.DestinationKey{}, target)
	addr.WithValue(proxy.InboundKey{}, c.LocalAddr())
	addr.WithContext(ctx)

	log.Debugf("new tcp connect from %v to %v\n", c.RemoteAddr(), addr)

	conn, err := y.Dialer.Conn(addr)
	if err != nil {
		return fmt.Errorf("dial %v failed: %w", addr, err)
	}
	defer conn.Close()

	relay.Relay(c, conn)

	return nil
}

func (y *yuubinsya) packet(c net.Conn) error {
	log.Debugln("new udp connect from", c.RemoteAddr())
	for {
		if err := y.remoteToLocal(c); err != nil {
			return fmt.Errorf("handle packet request failed: %w", err)
		}
	}
}

func (y *yuubinsya) remoteToLocal(c net.Conn) error {
	buf := pool.GetBytesV2(5 + 255 + 2 + nat.MaxSegmentSize)
	defer pool.PutBytesV2(buf)

	n, err := c.Read(buf.Bytes()[:4+255+2])
	if err != nil {
		return fmt.Errorf("read addr and length failed: %w", err)
	}

	addr, err := s5c.ResolveAddrBytes(buf.Bytes()[:4+255])
	if err != nil {
		return err
	}

	length := binary.BigEndian.Uint16(buf.Bytes()[len(addr):])

	if remain := int(length) + len(addr) + 2 - n; remain > 0 {
		if remain > len(buf.Bytes())-n {
			return fmt.Errorf("packet too large")
		}

		if _, err = io.ReadFull(c, buf.Bytes()[n:n+remain]); err != nil {
			return err
		}
	}

	src := c.RemoteAddr()
	if conn, ok := c.(interface{ StreamID() quicgo.StreamID }); ok {
		src = &quic.QuicAddr{Addr: c.RemoteAddr(), ID: conn.StreamID()}
	}

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()

	dst := addr.Address(statistic.Type_udp)
	dst.WithContext(ctx)

	return y.nat.Write(&nat.Packet{
		Src:     src,
		Dst:     dst,
		Payload: buf.Bytes()[len(addr)+2 : int(length)+len(addr)+2],
		WriteBack: func(buf []byte, from net.Addr) (int, error) {
			addr, err := proxy.ParseSysAddr(from)
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

	t.Write(conn)
}
