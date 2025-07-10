package yuubinsya

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type server struct {
	listener netapi.Listener
	hash     []byte

	coalesce bool
	handler  netapi.Handler
	ctx      context.Context
	cancel   context.CancelFunc
}

func init() {
	register.RegisterProtocol(NewServer)
}

func NewServer(config *pl.Yuubinsya, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	hash := Salt([]byte(config.GetPassword()))

	ctx, cancel := context.WithCancel(context.Background())
	s := &server{
		listener: ii,
		hash:     hash,
		coalesce: config.GetUdpCoalesce(),
		handler:  handler,
		ctx:      ctx,
		cancel:   cancel,
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
		Password:   y.hash,
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

func (y *server) handle(conn net.Conn) error {
	c := pool.NewBufioConnSize(conn, configuration.UDPBufferSize.Load())

	_ = conn.SetReadDeadline(time.Now().Add(time.Second * 30))
	header, err := Handshaker(y.hash).DecodeHeader(c)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("parse header failed: %w", err)
	}

	switch header.Protocol.Network() {
	case TCP:
		y.handler.HandleStream(&netapi.StreamMeta{
			Source:      c.RemoteAddr(),
			Destination: header.Addr,
			Inbound:     c.LocalAddr(),
			Src:         c,
			Address:     header.Addr,
		})

		return nil

	case UDP, UDPWithMigrateID:
		if header.Protocol.Network() == UDPWithMigrateID {
			if header.MigrateID == 0 {
				header.MigrateID = nat.GenerateID(c.RemoteAddr())
			}

			err = pool.BinaryWriteUint64(c, binary.BigEndian, header.MigrateID)
			if err != nil {
				return fmt.Errorf("write migrate id failed: %w", err)
			}
		}

		pc := newPacketConn(c, y.hash, y.coalesce)
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

			y.handler.HandlePacket(netapi.NewPacket(
				c.RemoteAddr(),
				dst,
				pool.Clone(buf[:n]),
				netapi.WriteBackFunc(func(b []byte, addr net.Addr) (int, error) {
					return pc.WriteTo(b, addr)
				}),
				netapi.WithMigrateID(header.MigrateID),
			))
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
