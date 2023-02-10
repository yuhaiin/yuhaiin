package yuubinsya

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

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
	TCP       Type = 1
	TLS       Type = 2
	QUIC      Type = 3
	WEBSOCKET Type = 4
	GRPC      Type = 5
)

type Config struct {
	Dialer    proxy.Proxy
	Host      string
	Password  []byte
	TlsConfig *tls.Config
	Type      Type
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
		handshaker: NewHandshaker(config.TlsConfig == nil, config.Password),
		nat:        nat.NewTable(config.Dialer),
	}
}

type wrapHijacker struct {
	http.ResponseWriter
	conn net.Conn
	buf  *bufio.ReadWriter
}

func (w *wrapHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.conn != nil {
		return w.conn, w.buf, nil
	}

	conn, buf, err := w.ResponseWriter.(http.Hijacker).Hijack()
	w.conn = conn
	w.buf = buf
	return conn, buf, err
}

func (y *yuubinsya) Start() error {
	var lis net.Listener
	var err error

	switch y.Type {

	}
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
			if err := y.handle(conn); err != nil {
				log.Errorln("handle failed:", err)
			}
		}()
	}
}

var (
	tcp byte = 66
	udp byte = 77
)

func (y *yuubinsya) handle(conn net.Conn) error {
	c, err := y.handshaker.handshakeServer(conn)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	z := make([]byte, 2)
	if _, err := io.ReadFull(c, z); err != nil {
		return fmt.Errorf("read net type failed: %w", err)
	}
	net, passwordLen := z[0], z[1]

	if passwordLen > 0 && (net == tcp || net == udp) {
		password := pool.GetBytesV2(passwordLen)
		defer pool.PutBytesV2(password)

		if _, err := io.ReadFull(c, password.Bytes()); err != nil {
			return fmt.Errorf("read password failed: %w", err)
		}

		if !bytes.Equal(password.Bytes(), y.Password) {
			return errors.New("password is incorrect")
		}
	}

	switch net {
	case tcp:
		return y.stream(c)
	case udp:
		return y.packet(c)
	default:
		return errors.New("unknown network")
	}
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

	addr := target.Address(statistic.Type_tcp)
	addr.WithValue(proxy.SourceKey{}, c.RemoteAddr())
	addr.WithValue(proxy.DestinationKey{}, target)
	addr.WithValue(proxy.InboundKey{}, c.LocalAddr())

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
	buf := pool.GetBytes(2 + nat.MaxSegmentSize + 4 + 255)
	defer pool.PutBytes(buf)

	n, err := c.Read(buf)
	if err != nil {
		return fmt.Errorf("read buf failed: %w", err)
	}

	addr, err := s5c.ResolveAddr(bytes.NewBuffer(buf))
	if err != nil {
		return err
	}

	addrLen := len(addr)

	if n == addrLen {
		if _, err := io.ReadFull(c, buf[addrLen:addrLen+2]); err != nil {
			return fmt.Errorf("read length failed: %w", err)
		}
		n += 2
	}

	length := int(binary.BigEndian.Uint16(buf[addrLen:]))

	if n-addrLen-2 < length {
		m, err := io.ReadFull(c, buf[n:length+addrLen+2])
		if err != nil {
			return fmt.Errorf("read payload failed: %w", err)
		}
		n += m
	}

	payload := buf[addrLen+2 : n]

	src := c.RemoteAddr()
	if conn, ok := c.(interface{ StreamID() quicgo.StreamID }); ok {
		src = &quic.QuicAddr{Addr: c.RemoteAddr(), ID: conn.StreamID()}
	}

	return y.nat.Write(&nat.Packet{
		SourceAddress:      src,
		DestinationAddress: addr.Address(statistic.Type_udp),
		Payload:            payload,
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
