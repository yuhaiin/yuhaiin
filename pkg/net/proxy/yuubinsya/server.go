package yuubinsya

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/entity"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
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

		go log.IfErr("yuubinsya udp server", s.startUDP)
		go log.IfErr("yuubinsya tcp server", s.startTCP)

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
			return err
		}

		go log.IfErr("yuubinsya tcp handle", func() error { return y.handle(conn) }, io.EOF, os.ErrDeadlineExceeded)
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
			packetConn := newPacketConn(c, y.handshaker, true)
			defer packetConn.Close()

			log.Debug("new udp connect", "from", packetConn.RemoteAddr())

			for {
				buf, addr, err := netapi.ReadFrom(packetConn)
				if err != nil {
					return err
				}

				select {
				case <-y.ctx.Done():
					return y.ctx.Err()
				case y.udpChannel <- &netapi.Packet{
					Src:       packetConn.RemoteAddr(),
					Dst:       addr,
					Payload:   buf,
					WriteBack: packetConn.WriteTo,
				}:
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
