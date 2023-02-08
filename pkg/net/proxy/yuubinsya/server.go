package yuubinsya

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	quicgo "github.com/quic-go/quic-go"
)

const (
	MaxPacketSize = 1024*64 - 1
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

func NewServer(config Config) (*yuubinsya, error) {
	log.Println(config)

	y := &yuubinsya{
		Config:     config,
		handshaker: NewHandshaker(true, config.TlsConfig != nil, config.Password),
		nat:        nat.NewTable(config.Dialer),
	}

	return y, nil

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

	if y.Type != QUIC {
		lis, err = net.Listen("tcp", y.Host)
		if err != nil {
			return err
		}

		if y.TlsConfig != nil {
			lis = tls.NewListener(lis, y.TlsConfig)
		}

		if y.Type == WEBSOCKET {
			lis = websocket.NewServer(lis)
		}

		defer lis.Close()
	} else {
		packetConn, err := net.ListenPacket("udp", y.Host)
		if err != nil {
			return err
		}
		defer packetConn.Close()
		lis, err = quic.NewServer(packetConn, y.TlsConfig)
		if err != nil {
			log.Fatal(err)
		}
		defer lis.Close()
	}

	log.Println(y.Type, "new server listen at:", lis.Addr())

	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}

			log.Println("accept failed:", err)
			continue
		}

		go func() {
			defer conn.Close()
			if err := y.handle(conn); err != nil {
				log.Println("handle failed:", err)
			}
		}()
	}
}

var (
	tcp byte = 66
	udp byte = 77
)

func (y *yuubinsya) handle(conn net.Conn) error {
	c, err := y.handshaker.handshake(conn)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	z := make([]byte, 2)
	if _, err := io.ReadFull(c, z); err != nil {
		return err
	}
	net, passwordLen := z[0], z[1]

	if passwordLen > 0 && (net == tcp || net == udp) {
		password := pool.GetBytesV2(passwordLen)
		defer pool.PutBytesV2(password)

		if _, err := io.ReadFull(c, password.Bytes()); err != nil {
			return err
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

func (y *yuubinsya) stream(c net.Conn) error {
	target, err := s5c.ResolveAddr(c)
	if err != nil {
		return err
	}

	addr := target.Address(statistic.Type_tcp)

	log.Printf("new tcp connect from %v to %v\n", c.RemoteAddr(), addr)

	conn, err := y.Dialer.Conn(addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.(*net.TCPConn).SetKeepAlive(false)

	relay.Relay(c, conn)

	return nil
}

func (y *yuubinsya) packet(c net.Conn) error {
	log.Println("new udp connect from", c.RemoteAddr())
	for {
		if err := y.remoteToLocal(c); err != nil {
			return err
		}
	}
}

func (y *yuubinsya) remoteToLocal(c net.Conn) error {
	addr, err := s5c.ResolveAddr(c)
	if err != nil {
		return err
	}

	var length uint16
	if err = binary.Read(c, binary.BigEndian, &length); err != nil {
		return err
	}

	buf := pool.GetBytesV2(int(length))
	defer pool.PutBytesV2(buf)

	if _, err = io.ReadFull(c, buf.Bytes()); err != nil {
		return err
	}

	src := c.RemoteAddr()
	if conn, ok := c.(interface{ StreamID() quicgo.StreamID }); ok {
		src = &quic.QuicAddr{Addr: c.RemoteAddr(), ID: conn.StreamID()}
	}

	return y.nat.Write(&nat.Packet{
		SourceAddress:      src,
		DestinationAddress: addr.Address(statistic.Type_udp),
		Payload:            buf.Bytes(),
		WriteBack: func(buf []byte, from net.Addr) (int, error) {
			addr, err := proxy.ParseSysAddr(from)
			if err != nil {
				return 0, err
			}

			buffer := pool.GetBuffer()
			defer pool.PutBuffer(buffer)
			s5c.ParseAddrWriter(addr, buffer)
			if err = binary.Write(buffer, binary.BigEndian, uint16(len(buf))); err != nil {
				return 0, err
			}
			buffer.Write(buf)

			if _, err := c.Write(buffer.Bytes()); err != nil {
				return 0, err
			}

			return len(buf), nil
		},
	})
}
