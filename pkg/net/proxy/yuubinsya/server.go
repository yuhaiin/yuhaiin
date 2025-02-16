package yuubinsya

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/plain"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type server struct {
	listener   netapi.Listener
	handshaker types.Handshaker

	handler    netapi.Handler
	packetAuth types.Auth
	ctx        context.Context
	cancel     context.CancelFunc
}

func init() {
	register.RegisterProtocol(NewServer)
}

func NewServer(config *pl.Yuubinsya, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	auth, err := NewAuth(config.GetUdpEncrypt(), []byte(config.GetPassword()))
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &server{
		listener: ii,
		handshaker: NewHandshaker(
			true,
			config.GetTcpEncrypt(),
			[]byte(config.GetPassword()),
		),

		handler:    handler,
		packetAuth: auth,
		ctx:        ctx,
		cancel:     cancel,
	}

	go log.IfErr("yuubinsya udp server", s.startUDP, errors.ErrUnsupported)
	go log.IfErr("yuubinsya tcp server", s.startTCP, net.ErrClosed)

	return s, nil
}

func (y *server) startUDP() error {
	packet, err := y.listener.Packet(y.ctx)
	if err != nil {
		return err
	}
	defer packet.Close()

	return (&UDPServer{
		PacketConn: packet,
		Handler:    y.handler.HandlePacket,
		Auth:       y.packetAuth,
	}).Serve()
}

func (y *server) startTCP() (err error) {
	lis, err := y.listener.Stream(y.ctx)
	if err != nil {
		return err
	}
	defer lis.Close()

	log.Info("new yuubinsya server", "host", lis.Addr())

	for {
		conn, err := lis.Accept()
		if err != nil {
			return err
		}

		go func() {
			if err := y.handle(conn); err != nil && !errors.Is(err, io.EOF) {
				// [syscall.ETIMEDOUT] connection timed out
				// UNIX® Network Programming book by Richard Stevens says the following..
				// If the client TCP receives no response to its SYN segment, ETIMEDOUT is returned.
				// 4.4BSD, for example, sends one SYN when connect is called, another 6 seconds later,
				// and another 24 seconds later (p. 828 of TCPv2).
				// If no response is received after a total of 75 seconds, the error is returned.
				//
				// maybe blow
				//
				// ETIMEDOUT is almost certainly a response to a previous send().
				// send() is asynchronous. If it doesn't return -1,
				// all that means is that data was transferred into the local socket send buffer.
				// It is sent, or not sent, asynchronously,
				// and if there was an error in that process it can only be delivered
				// via the next system call: in this case, recv().
				log.Error("yuubinsya tcp handle failed", "err", err)
			}
		}()
	}
}

var nginx404, _ = base64.StdEncoding.DecodeString("PGh0bWw+DQo8aGVhZD48dGl0bGU+NDA0IE5vdCBGb3VuZDwvdGl0bGU+PC9oZWFkPg0KPGJvZHk+DQo8Y2VudGVyPjxoMT40MDQgTm90IEZvdW5kPC9oMT48L2NlbnRlcj4NCjxocj48Y2VudGVyPm5naW54LzEuMjYuMzwvY2VudGVyPg0KPC9ib2R5Pg0KPC9odG1sPg0K")

func write404(conn net.Conn) {
	r := http.Response{
		Status:        http.StatusText(http.StatusNotFound),
		StatusCode:    http.StatusNotFound,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewReader(nginx404)),
		ContentLength: int64(len(nginx404)),
		Close:         true,
		Header:        make(http.Header),
	}

	r.Header.Set("Server", "nginx/1.26.3")
	r.Header.Set("Date", time.Now().Format(time.RFC1123))
	r.Header.Set("Content-Type", "text/html")

	_ = r.Write(conn)
}

func (y *server) handle(conn net.Conn) error {
	cc, err := y.handshaker.Handshake(conn)
	if err != nil {
		write404(conn)
		return fmt.Errorf("handshake failed: %w", err)
	}

	c := pool.NewBufioConnSize(cc, configuration.UDPBufferSize.Load())

	_ = conn.SetReadDeadline(time.Now().Add(time.Second * 6))
	header, err := y.handshaker.DecodeHeader(c)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		write404(c)
		return fmt.Errorf("parse header failed: %w", err)
	}

	switch header.Protocol.Network() {
	case types.TCP:
		y.handler.HandleStream(&netapi.StreamMeta{
			Source:      c.RemoteAddr(),
			Destination: header.Addr,
			Inbound:     c.LocalAddr(),
			Src:         c,
			Address:     header.Addr,
		})

		return nil

	case types.UDP, types.UDPWithMigrateID:
		if header.Protocol.Network() == types.UDPWithMigrateID {
			if header.MigrateID == 0 {
				header.MigrateID = nat.GenerateID(c.RemoteAddr())
			}

			err = pool.BinaryWriteUint64(c, binary.BigEndian, header.MigrateID)
			if err != nil {
				return fmt.Errorf("write migrate id failed: %w", err)
			}
		}

		pc := newPacketConn(c, y.handshaker)
		defer pc.Close()

		log.Debug("new udp connect", "from", c.RemoteAddr(), "migrate id", header.MigrateID)

		buf := pool.GetBytes(configuration.UDPBufferSize.Load())
		defer pool.PutBytes(buf)

		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return fmt.Errorf("read udp request failed: %w", err)
			}

			dst, err := netapi.ParseSysAddr(addr)
			if err != nil {
				continue
			}

			y.handler.HandlePacket(&netapi.Packet{
				Src:       c.RemoteAddr(),
				Dst:       dst,
				Payload:   pool.Clone(buf[:n]),
				WriteBack: pc,
				MigrateID: header.MigrateID,
			})
		}
	}

	return nil
}

func (y *server) Close() error {
	y.cancel()
	if y.listener == nil {
		return nil
	}
	return y.listener.Close()
}

func NewHandshaker(server bool, encrypted bool, password []byte) types.Handshaker {
	hash := types.Salt(password)

	if !encrypted {
		return plain.Handshaker(hash)
	}

	return crypto.NewHandshaker(server, hash, password)
}

func NewAuth(crypt bool, password []byte) (types.Auth, error) {
	password = types.Salt(password)

	if !crypt {
		return plain.NewAuth(password), nil
	}

	return crypto.GetAuth(password)
}
