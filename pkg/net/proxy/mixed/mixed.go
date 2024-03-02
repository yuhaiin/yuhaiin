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

	s5c *netapi.ChannelListener
	s5  netapi.ProtocolServer

	s4c *netapi.ChannelListener
	s4  netapi.ProtocolServer

	httpc *netapi.ChannelListener
	http  netapi.ProtocolServer

	*netapi.ChannelProtocolServer
}

func init() {
	listener.RegisterProtocol(NewServer)
}

func NewServer(o *listener.Inbound_Mix) func(lis netapi.Listener) (netapi.ProtocolServer, error) {
	return func(ii netapi.Listener) (netapi.ProtocolServer, error) {
		lis, err := ii.Stream(context.TODO())
		if err != nil {
			return nil, err
		}

		mix := &Mixed{
			lis:                   lis,
			ChannelProtocolServer: netapi.NewChannelProtocolServer(),
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
		s5 := mix.s5.(*s5s.Socks5)
		s5.ChannelProtocolServer.Close()
		s5.ChannelProtocolServer = mix.ChannelProtocolServer

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
		s4 := mix.s4.(*socks4a.Server)
		s4.ChannelProtocolServer.Close()
		s4.ChannelProtocolServer = mix.ChannelProtocolServer

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
		http := mix.http.(*httpproxy.Server)
		http.ChannelProtocolServer.Close()
		http.ChannelProtocolServer = mix.ChannelProtocolServer

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
	m.ChannelProtocolServer.Close()
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
