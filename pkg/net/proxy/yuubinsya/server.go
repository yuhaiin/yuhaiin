package yuubinsya

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type server struct {
	Listener   netapi.Listener
	handshaker crypto.Handshaker

	*netapi.ChannelProtocolServer

	packetAuth Auth
}

func init() {
	pl.RegisterProtocol(NewServer)
}

func NewServer(config *pl.Inbound_Yuubinsya) func(netapi.Listener) (netapi.ProtocolServer, error) {
	return func(ii netapi.Listener) (netapi.ProtocolServer, error) {
		auth, err := NewAuth(!config.Yuubinsya.ForceDisableEncrypt, []byte(config.Yuubinsya.Password))
		if err != nil {
			return nil, err
		}

		s := &server{
			Listener: ii,
			handshaker: NewHandshaker(
				true,
				!config.Yuubinsya.ForceDisableEncrypt,
				[]byte(config.Yuubinsya.Password),
			),

			ChannelProtocolServer: netapi.NewChannelProtocolServer(),
			packetAuth:            auth,
		}

		go log.IfErr("yuubinsya udp server", s.startUDP)
		go log.IfErr("yuubinsya tcp server", s.startTCP)

		return s, nil
	}
}

func (y *server) startUDP() error {
	packet, err := y.Listener.Packet(y.Context())
	if err != nil {
		return err
	}
	defer packet.Close()

	StartUDPServer(packet, y.NewPacket, y.packetAuth, true)

	return nil
}

func (y *server) startTCP() (err error) {
	lis, err := y.Listener.Stream(y.Context())
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
	c, err := y.handshaker.Handshake(conn)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	net, err := y.handshaker.DecodeHeader(c)
	if err != nil {
		return fmt.Errorf("parse header failed: %w", err)
	}

	switch net {
	case crypto.TCP:
		target, err := tools.ResolveAddr(c)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}

		addr := target.Address(statistic.Type_tcp)

		if !y.NewStream(&netapi.StreamMeta{
			Source:      c.RemoteAddr(),
			Destination: addr,
			Inbound:     c.LocalAddr(),
			Src:         c,
			Address:     addr,
		}) {
			return nil
		}

	case crypto.UDP:
		return func() error {
			packetConn := newPacketConn(c, y.handshaker, true)
			defer packetConn.Close()

			log.Debug("new udp connect", "from", packetConn.RemoteAddr())

			for {
				buf, addr, err := netapi.ReadFrom(packetConn)
				if err != nil {
					return err
				}
				if !y.NewPacket(&netapi.Packet{
					Src:       packetConn.RemoteAddr(),
					Dst:       addr,
					Payload:   buf,
					WriteBack: packetConn.WriteTo,
				}) {
					return nil
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
