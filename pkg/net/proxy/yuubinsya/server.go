package yuubinsya

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/crypto"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/plain"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
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
	pl.RegisterProtocol(NewServer)
}

func NewServer(config *pl.Inbound_Yuubinsya) func(netapi.Listener, netapi.Handler) (netapi.Accepter, error) {
	return func(ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
		auth, err := NewAuth(config.Yuubinsya.GetUdpEncrypt(), []byte(config.Yuubinsya.Password))
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithCancel(context.Background())
		s := &server{
			listener: ii,
			handshaker: NewHandshaker(
				true,
				config.Yuubinsya.GetTcpEncrypt(),
				[]byte(config.Yuubinsya.Password),
			),

			handler:    handler,
			packetAuth: auth,
			ctx:        ctx,
			cancel:     cancel,
		}

		go log.IfErr("yuubinsya udp server", s.startUDP)
		go log.IfErr("yuubinsya tcp server", s.startTCP)

		return s, nil
	}
}

func (y *server) startUDP() error {
	packet, err := y.listener.Packet(y.ctx)
	if err != nil {
		return err
	}
	defer packet.Close()

	StartUDPServer(packet, y.handler.HandlePacket, y.packetAuth, false)

	return nil
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
				log.Error("yuubinsya tcp handle failed", "err", err)
			}
		}()
	}
}

func (y *server) handle(conn net.Conn) error {
	c, err := y.handshaker.Handshake(conn)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	header, err := y.handshaker.DecodeHeader(c)
	if err != nil {
		return fmt.Errorf("parse header failed: %w", err)
	}

	switch header.Protocol {
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
		if header.Protocol == types.UDPWithMigrateID {
			if header.MigrateID == 0 {
				header.MigrateID = nat.GenerateID(c.RemoteAddr())
			}

			err = binary.Write(c, binary.BigEndian, header.MigrateID)
			if err != nil {
				return fmt.Errorf("write migrate id failed: %w", err)
			}
		}

		pc := newPacketConn(c, y.handshaker)
		defer pc.Close()

		log.Debug("new udp connect", "from", c.RemoteAddr(), "migrate id", header.MigrateID)

		buf := pool.GetBytes(nat.MaxSegmentSize)
		defer pool.PutBytes(buf)

		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return err
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
