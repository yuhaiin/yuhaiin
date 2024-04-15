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
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/plain"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type server struct {
	listener   netapi.Listener
	handshaker types.Handshaker

	*netapi.ChannelServer

	packetAuth types.Auth
}

func init() {
	pl.RegisterProtocol(NewServer)
}

func NewServer(config *pl.Inbound_Yuubinsya) func(netapi.Listener) (netapi.Accepter, error) {
	return func(ii netapi.Listener) (netapi.Accepter, error) {
		auth, err := NewAuth(config.Yuubinsya.GetUdpEncrypt(), []byte(config.Yuubinsya.Password))
		if err != nil {
			return nil, err
		}

		s := &server{
			listener: ii,
			handshaker: NewHandshaker(
				true,
				config.Yuubinsya.GetTcpEncrypt(),
				[]byte(config.Yuubinsya.Password),
			),

			ChannelServer: netapi.NewChannelServer(),
			packetAuth:    auth,
		}

		go log.IfErr("yuubinsya udp server", s.startUDP)
		go log.IfErr("yuubinsya tcp server", s.startTCP)

		return s, nil
	}
}

func (y *server) startUDP() error {
	packet, err := y.listener.Packet(y.Context())
	if err != nil {
		return err
	}
	defer packet.Close()

	StartUDPServer(packet, y.SendPacket, y.packetAuth, true)

	return nil
}

func (y *server) startTCP() (err error) {
	lis, err := y.listener.Stream(y.Context())
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
	case types.TCP:
		target, err := tools.ResolveAddr(c)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}

		addr := target.Address(statistic.Type_tcp)

		return y.SendStream(&netapi.StreamMeta{
			Source:      c.RemoteAddr(),
			Destination: addr,
			Inbound:     c.LocalAddr(),
			Src:         c,
			Address:     addr,
		})

	case types.UDP:
		pc := newPacketConn(c, y.handshaker, true)
		defer pc.Close()

		log.Debug("new udp connect", "from", pc.RemoteAddr())

		for {
			buf, addr, err := netapi.ReadFrom(pc)
			if err != nil {
				return err
			}
			err = y.SendPacket(&netapi.Packet{
				Src:       pc.RemoteAddr(),
				Dst:       addr,
				Payload:   buf,
				WriteBack: pc.WriteTo,
			})

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (y *server) Close() error {
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
