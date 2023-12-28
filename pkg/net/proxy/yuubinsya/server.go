package yuubinsya

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/entity"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type server struct {
	Listener   netapi.Listener
	handshaker entity.Handshaker

	ctx    context.Context
	cancel context.CancelFunc

	tcpChannel chan *netapi.StreamMeta
	udpChannel chan *netapi.Packet

	packetAuth Auth
}

func init() {
	pl.RegisterProtocol2(NewServer)
}

func NewServer(config *pl.Inbound_Yuubinsya) func(netapi.Listener) (netapi.ProtocolServer, error) {
	return func(ii netapi.Listener) (netapi.ProtocolServer, error) {
		auth, err := NewAuth(!config.Yuubinsya.ForceDisableEncrypt, []byte(config.Yuubinsya.Password))
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithCancel(context.TODO())
		s := &server{
			Listener:   ii,
			handshaker: NewHandshaker(!config.Yuubinsya.ForceDisableEncrypt, []byte(config.Yuubinsya.Password)),
			ctx:        ctx,
			cancel:     cancel,
			tcpChannel: make(chan *netapi.StreamMeta, 100),
			udpChannel: make(chan *netapi.Packet, 100),
			packetAuth: auth,
		}

		go func() {
			if err := s.startUDP(); err != nil {
				log.Error("yuubinsya server failed:", "err", err)
			}
		}()

		go func() {
			if err := s.startTCP(); err != nil {
				log.Error("yuubinsya server failed:", "err", err)
			}
		}()

		return s, nil
	}
}

func (y *server) startUDP() error {
	packet, err := y.Listener.Packet(y.ctx)
	if err != nil {
		return err
	}
	defer packet.Close()

	StartUDPServer(y.ctx, packet, y.udpChannel, y.packetAuth, true)

	return nil
}

func (y *server) startTCP() (err error) {
	lis, err := y.Listener.Stream(y.ctx)
	if err != nil {
		return err
	}
	defer lis.Close()

	log.Info("new yuubinsya server", "host", lis.Addr())

	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Error("accept failed", "err", err)
			return err
		}

		go func() {
			if err := y.handle(conn); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Error("handle failed", slog.Any("from", conn.RemoteAddr()), slog.Any("err", err))
			}
		}()
	}
}

func (y *server) handle(conn net.Conn) error {
	c, err := y.handshaker.HandshakeServer(conn)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	net, err := y.handshaker.ParseHeader(c)
	if err != nil {
		return fmt.Errorf("parse header failed: %w", err)
	}

	switch net {
	case entity.TCP:
		target, err := tools.ResolveAddr(c)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}

		addr := target.Address(statistic.Type_tcp)

		select {
		case <-y.ctx.Done():
			return y.ctx.Err()
		case y.tcpChannel <- &netapi.StreamMeta{
			Source:      c.RemoteAddr(),
			Destination: addr,
			Inbound:     c.LocalAddr(),
			Src:         c,
			Address:     addr,
		}:
		}
	case entity.UDP:
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

func (y *server) Close() error {
	if y.Listener == nil {
		return nil
	}
	return y.Listener.Close()
}

func (y *server) forwardPacket(c net.Conn) error {
	addr, err := tools.ResolveAddr(c)
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

	select {
	case <-y.ctx.Done():
		return y.ctx.Err()
	case y.udpChannel <- &netapi.Packet{
		Src:     c.RemoteAddr(),
		Dst:     addr.Address(statistic.Type_udp),
		Payload: bufv2,
		WriteBack: func(buf []byte, from net.Addr) (int, error) {
			addr, err := netapi.ParseSysAddr(from)
			if err != nil {
				return 0, err
			}

			buffer := pool.GetBuffer()
			defer pool.PutBuffer(buffer)

			tools.ParseAddrWriter(addr, buffer)
			err = binary.Write(buffer, binary.BigEndian, uint16(len(buf)))
			if err != nil {
				return 0, err
			}
			_, err = buffer.Write(buf)
			if err != nil {
				return 0, err
			}

			if _, err := c.Write(buffer.Bytes()); err != nil {
				return 0, err
			}

			return len(buf), nil
		},
	}:
	}
	return nil
}

func (y *server) AcceptStream() (*netapi.StreamMeta, error) {
	select {
	case <-y.ctx.Done():
		return nil, y.ctx.Err()
	case meta := <-y.tcpChannel:
		return meta, nil
	}
}
func (y *server) AcceptPacket() (*netapi.Packet, error) {
	select {
	case <-y.ctx.Done():
		return nil, y.ctx.Err()
	case packet := <-y.udpChannel:
		return packet, nil
	}
}
