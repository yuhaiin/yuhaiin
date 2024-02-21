package mixed

import (
	"context"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	httpproxy "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	s5s "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Mixed struct {
	lis net.Listener

	ctx   context.Context
	close context.CancelFunc

	s5c *netapi.ChannelListener
	s5  netapi.ProtocolServer

	s4c *netapi.ChannelListener
	s4  netapi.ProtocolServer

	httpc *netapi.ChannelListener
	http  netapi.ProtocolServer

	tcpChannel chan *netapi.StreamMeta
	udpChannel chan *netapi.Packet
}

func init() {
	listener.RegisterProtocol2(NewServer)
}

func NewServer(o *listener.Inbound_Mix) func(lis netapi.Listener) (netapi.ProtocolServer, error) {
	return func(ii netapi.Listener) (netapi.ProtocolServer, error) {
		lis, err := ii.Stream(context.TODO())
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithCancel(context.Background())
		mix := &Mixed{
			lis:        lis,
			ctx:        ctx,
			close:      cancel,
			tcpChannel: make(chan *netapi.StreamMeta, 100),
			udpChannel: make(chan *netapi.Packet, 100),
		}

		mix.s5c = netapi.NewChannelListener(lis.Addr())
		mix.s5, err = s5s.NewServer(&listener.Inbound_Socks5{
			Socks5: &listener.Socks5{
				Host:     o.Mix.Host,
				Username: o.Mix.Username,
				Password: o.Mix.Password,
				Udp:      true,
			},
		})(netapi.ListenWrap(mix.s5c, ii))
		if err != nil {
			mix.Close()
			return nil, err
		}
		mix.NewChanInbound(mix.s5)

		mix.s4c = netapi.NewChannelListener(lis.Addr())
		mix.s4, err = socks4a.NewServer(&listener.Inbound_Socks4A{
			Socks4A: &listener.Socks4A{
				Host:     o.Mix.Host,
				Username: o.Mix.Username,
			},
		})(netapi.ListenWrap(mix.s4c, ii))
		if err != nil {
			mix.Close()
			return nil, err
		}
		mix.NewChanInbound(mix.s4)

		mix.httpc = netapi.NewChannelListener(lis.Addr())
		mix.http, err = httpproxy.NewServer(&listener.Inbound_Http{
			Http: &listener.Http{
				Host:     o.Mix.Host,
				Username: o.Mix.Username,
				Password: o.Mix.Password,
			},
		})(netapi.ListenWrap(mix.httpc, ii))
		if err != nil {
			mix.Close()
			return nil, err
		}
		mix.NewChanInbound(mix.http)

		go func() {
			defer mix.Close()
			if err := mix.handle(); err != nil {
				log.Debug("mixed handle failed", "err", err)
			}
		}()

		return mix, nil
	}
}

func (m *Mixed) Close() error {
	m.close()
	noneNilClose(m.s5c)
	noneNilClose(m.s5)
	noneNilClose(m.s4c)
	noneNilClose(m.s4)
	noneNilClose(m.httpc)
	noneNilClose(m.http)
	return m.lis.Close()
}

func noneNilClose(i io.Closer) {
	if c, ok := i.(*netapi.ChannelListener); ok {
		if c != nil {
			_ = c.Close()
		}

		return
	}

	if i != nil {
		_ = i.Close()
	}
}

func (m *Mixed) handle() error {
	for {
		conn, err := m.lis.Accept()
		if err != nil {
			log.Error("mixed accept failed", "err", err)

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}

		go func() {
			protocol := pool.GetBytesBuffer(pool.DefaultSize)

			n, err := conn.Read(protocol.Bytes())
			if err != nil || n <= 0 {
				conn.Close()
				return
			}

			protocol.ResetSize(0, n)

			conn = netapi.NewPrefixBytesConn(conn, protocol)

			switch protocol.Bytes()[0] {
			case 0x05:
				m.s5c.NewConn(conn)
			case 0x04:
				m.s4c.NewConn(conn)
			default:
				m.httpc.NewConn(conn)
			}
		}()
	}
}

func (s *Mixed) AcceptStream() (*netapi.StreamMeta, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case meta := <-s.tcpChannel:
		return meta, nil
	}
}

func (s *Mixed) AcceptPacket() (*netapi.Packet, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case packet := <-s.udpChannel:
		return packet, nil
	}
}

func (m *Mixed) NewChanInbound(s netapi.ProtocolServer) {
	go func() {
		for {
			stream, err := s.AcceptStream()
			if err != nil {
				return
			}

			select {
			case <-m.ctx.Done():
				return
			case m.tcpChannel <- stream:
			}
		}
	}()

	go func() {
		for {
			packet, err := s.AcceptPacket()
			if err != nil {
				return
			}

			select {
			case <-m.ctx.Done():
				return
			case m.udpChannel <- packet:
			}
		}
	}()
}
