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
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	ws "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/websocket"
)

const (
	MaxPacketSize = 1024*64 - 1
)

type yuubinsya struct {
	addr     string
	password []byte

	Lis net.Listener

	handshaker handshaker

	dialer proxy.Proxy

	nat *nat.Table
}

func NewServer(dialer proxy.Proxy, host, password string, certPEM, keyPEM []byte, quicOrWs bool) (*yuubinsya, error) {
	var tlsConfig *tls.Config
	if certPEM != nil && keyPEM != nil {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	y := &yuubinsya{
		dialer:     dialer,
		addr:       host,
		password:   []byte(password),
		handshaker: NewHandshaker(true, quicOrWs, []byte(password), tlsConfig),
		nat:        nat.NewTable(dialer),
	}

	return y, nil

}

func (y *yuubinsya) StartWebsocket() error {
	lis, err := net.Listen("tcp", y.addr)
	if err != nil {
		return err
	}
	defer lis.Close()

	log.Println("new websocket server listen at:", lis.Addr())

	return http.Serve(tls.NewListener(lis,
		y.handshaker.(*tlsHandshaker).tlsConfig),
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

			if strings.ToLower(req.Header.Get("Upgrade")) != "websocket" ||
				!strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
				w.Write([]byte(`<!DOCTYPE html><html><head><style>body { max-width:400px; margin: 0 auto; }</style><title>A8.net</title></head><body>あなたのIPアドレスは ` + req.Header.Get("Cf-Connecting-Ip") + `<br/>A8スタッフブログ <a href="https://a8pr.jp">https://a8pr.jp</a></body></html>`))
				return
			}

			w = &wrapHijacker{ResponseWriter: w}

			(&websocket.Server{
				Config: websocket.Config{},
				Handler: func(c *websocket.Conn) {
					defer c.Close()

					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						log.Println("hijack failed:", err)
						return
					}

					if err := y.handle(&ws.Connection{Conn: c, RawConn: conn}); err != nil {
						log.Println("websocket handle failed:", err)
					}
				},
			}).ServeHTTP(w, req)
		}))
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
	lis, err := net.Listen("tcp", y.addr)
	if err != nil {
		return err
	}
	defer lis.Close()

	log.Println("new server listen at:", lis.Addr())

	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}

			log.Println("accept failed:", err)
			continue
		}

		conn.(*net.TCPConn).SetKeepAlive(true)

		go func() {
			defer conn.Close()
			if err := y.handle(conn); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Println("handle failed:", err)
			}
		}()
	}
}

func (y *yuubinsya) StartQUIC() error {
	tlsConfig := y.handshaker.(*tlsHandshaker).tlsConfig
	tlsConfig.NextProtos = []string{"hyperledger-fabric"}
	lis, err := quic.ListenAddrEarly(y.addr, tlsConfig, &quic.Config{
		MaxIncomingStreams: 2048,
		KeepAlivePeriod:    0,
		MaxIdleTimeout:     60 * time.Second,
		EnableDatagrams:    true,
	})
	if err != nil {
		return err
	}
	defer lis.Close()

	log.Println("new server listen at:", lis.Addr())

	for {
		conn, err := lis.Accept(context.TODO())
		if err != nil {
			return err
		}
		go func() {
			defer conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")

			/*
				because of https://github.com/quic-go/quic-go/blob/5b72f4c900f209b5705bb0959399d59e495a2c6e/internal/protocol/params.go#L137
				MaxDatagramFrameSize Too short, here use stream trans udp data until quic-go will auto frag lager frame
					// udp
					go func() {
						for {
							data, err := conn.ReceiveMessage()
							if err != nil {
								log.Println("receive message failed:", err)
								break
							}

							if err = y.handleQuicDatagram(data, conn); err != nil {
								log.Println("handle datagram failed:", err)
							}
						}
					}()
			*/
			for {
				stream, err := conn.AcceptStream(context.TODO())
				if err != nil {
					return
				}

				go func() {
					log.Println("new quic conn from", conn.RemoteAddr(), "id", stream.StreamID())

					conn := &interConn{
						Stream: stream,
						local:  conn.LocalAddr(),
						remote: conn.RemoteAddr(),
					}
					defer conn.Close()

					if err := y.handle(conn); err != nil {
						log.Println("handle failed:", err)
					}
				}()
			}
		}()
	}
}

func (c *yuubinsya) handleQuicDatagram(b []byte, session quic.Connection) error {
	if len(b) <= 5 {
		return fmt.Errorf("invalid datagram")
	}

	id := binary.BigEndian.Uint16(b[:2])
	addr, err := s5c.ResolveAddr(bytes.NewBuffer(b[2:]))
	if err != nil {
		return err
	}

	log.Println("new udp from", session.RemoteAddr(), "id", id, "to", addr.Address(statistic.Type_udp))

	return c.nat.Write(&nat.Packet{
		SourceAddress: &quicAddr{
			addr: session.RemoteAddr(),
			id:   quic.StreamID(id),
		},
		DestinationAddress: addr.Address(statistic.Type_udp),
		Payload:            b[2+len(addr):],
		WriteBack: func(b []byte, addr net.Addr) (int, error) {
			add, err := proxy.ParseSysAddr(addr)
			if err != nil {
				return 0, err
			}

			buf := pool.GetBuffer()
			defer pool.PutBuffer(buf)

			binary.Write(buf, binary.BigEndian, id)
			s5c.ParseAddrWriter(add, buf)
			buf.Write(b)

			// log.Println("write back to", session.RemoteAddr(), "id", id)
			if err = session.SendMessage(buf.Bytes()); err != nil {
				return 0, err
			}

			return len(b), nil
		},
	})
}

var _ net.Conn = (*interConn)(nil)

type interConn struct {
	quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *interConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

func (c *interConn) LocalAddr() net.Addr  { return c.local }
func (c *interConn) RemoteAddr() net.Addr { return c.remote }

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

		if !bytes.Equal(password.Bytes(), y.password) {
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

	conn, err := y.dialer.Conn(addr)
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
	if conn, ok := c.(interface{ StreamID() quic.StreamID }); ok {
		src = &quicAddr{c.RemoteAddr(), conn.StreamID()}
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

type quicAddr struct {
	addr net.Addr
	id   quic.StreamID
}

func (q *quicAddr) String() string  { return fmt.Sprint(q.addr, q.id) }
func (q *quicAddr) Network() string { return "quic" }
