package yuubinsya

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/quic-go/quic-go"
)

const (
	MaxPacketSize = 1024*64 - 1
)

type yuubinsya struct {
	addr     string
	password []byte

	Lis net.Listener

	handshaker handshaker
}

func NewServer(host, password string, certPEM, keyPEM []byte, quic bool) (*yuubinsya, error) {
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
		addr:       host,
		password:   []byte(password),
		handshaker: NewHandshaker(true, quic, []byte(password), tlsConfig),
	}

	return y, nil

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
	lis, err := quic.ListenAddr(y.addr, tlsConfig, nil)
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

			for {
				stream, err := conn.AcceptStream(context.TODO())
				if err != nil {
					return
				}

				go func() {
					defer stream.Close()

					log.Println("new quic conn from", conn.RemoteAddr())

					conn := &interConn{
						Stream: stream,
						local:  conn.LocalAddr(),
						remote: conn.RemoteAddr(),
					}

					if err := y.handle(conn); err != nil {
						log.Println("handle failed:", err)
					}
				}()
			}
		}()
	}
}

var _ net.Conn = (*interConn)(nil)

type interConn struct {
	quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *interConn) LocalAddr() net.Addr {
	return c.local
}

func (c *interConn) RemoteAddr() net.Addr {
	return c.remote
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
	addr := target.Address(statistic.Type_tcp).String()

	log.Printf("new tcp connect from %v to %v\n", c.RemoteAddr(), addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.(*net.TCPConn).SetKeepAlive(false)

	errChan := make(chan error)
	go func() { errChan <- relay.Copy(conn, c) }()
	relay.Copy(c, conn)
	<-errChan
	return nil
}

func (y *yuubinsya) packet(c net.Conn) error {
	log.Println("new udp connect from", c.RemoteAddr())

	packetConn, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	defer packetConn.Close()

	go func() {
		buf := pool.GetBytes(MaxPacketSize)
		defer pool.PutBytes(buf)
		buffer := pool.GetBuffer()
		defer pool.PutBuffer(buffer)

		for {
			if err := localToRemote(buf, buffer, c, packetConn); err != nil {
				return
			}
		}
	}()

	for {
		if err = remoteToLocal(c, packetConn); err != nil {
			return err
		}
	}
}

func localToRemote(buf []byte, buffer *bytes.Buffer, c net.Conn, local net.PacketConn) error {
	local.SetReadDeadline(time.Now().Add(time.Minute))
	n, from, err := local.ReadFrom(buf)
	if err != nil {
		return err
	}

	addr, err := proxy.ParseSysAddr(from)
	if err != nil {
		return err
	}

	buffer.Reset()
	s5c.ParseAddrWriter(addr, buffer)
	if err = binary.Write(buffer, binary.BigEndian, uint16(n)); err != nil {
		return err
	}
	buffer.Write(buf[:n])

	if _, err := c.Write(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}

func remoteToLocal(c net.Conn, local net.PacketConn) error {
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

	paddr := addr.Address(statistic.Type_udp)

	udpAddr, err := paddr.UDPAddr()
	if err != nil {
		return err
	}
	if _, err = local.WriteTo(buf.Bytes(), udpAddr); err != nil {
		return err
	}

	return nil
}
