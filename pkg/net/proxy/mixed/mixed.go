package mixed

import (
	"context"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Mixed struct {
	lis net.Listener

	s5c *netapi.ChannelListener
	s5  netapi.Accepter

	s4c *netapi.ChannelListener
	s4  netapi.Accepter

	httpc *netapi.ChannelListener
	http  netapi.Accepter

	*netapi.ChannelServer
}

func init() {
	listener.RegisterProtocol(NewServer)
}

func NewServer(o *listener.Inbound_Mix) func(lis netapi.Listener) (netapi.Accepter, error) {
	return func(ii netapi.Listener) (netapi.Accepter, error) {
		lis, err := ii.Stream(context.TODO())
		if err != nil {
			return nil, err
		}

		mix := &Mixed{
			lis:           lis,
			ChannelServer: netapi.NewChannelServer(),
		}

		mix.s5c = netapi.NewChannelListener(lis.Addr())
		mix.s5, err = socks5.NewServer(&listener.Inbound_Socks5{
			Socks5: &listener.Socks5{
				Host:     o.Mix.Host,
				Username: o.Mix.Username,
				Password: o.Mix.Password,
				Udp:      true,
			},
		})(netapi.PatchStream(mix.s5c, ii))
		if err != nil {
			mix.Close()
			return nil, err
		}
		s5 := mix.s5.(*socks5.Server)
		s5.ChannelServer.Close()
		s5.ChannelServer = mix.ChannelServer

		mix.s4c = netapi.NewChannelListener(lis.Addr())
		mix.s4, err = socks4a.NewServer(&listener.Inbound_Socks4A{
			Socks4A: &listener.Socks4A{
				Host:     o.Mix.Host,
				Username: o.Mix.Username,
			},
		})(netapi.PatchStream(mix.s4c, ii))
		if err != nil {
			mix.Close()
			return nil, err
		}
		s4 := mix.s4.(*socks4a.Server)
		s4.ChannelServer.Close()
		s4.ChannelServer = mix.ChannelServer

		mix.httpc = netapi.NewChannelListener(lis.Addr())
		mix.http, err = http.NewServer(&listener.Inbound_Http{
			Http: &listener.Http{
				Host:     o.Mix.Host,
				Username: o.Mix.Username,
				Password: o.Mix.Password,
			},
		})(netapi.PatchStream(mix.httpc, ii))
		if err != nil {
			mix.Close()
			return nil, err
		}
		http := mix.http.(*http.Server)
		http.ChannelServer.Close()
		http.ChannelServer = mix.ChannelServer

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
	m.ChannelServer.Close()
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
			protocol := pool.GetBytes(pool.DefaultSize)

			n, err := conn.Read(protocol)
			if err != nil || n <= 0 {
				conn.Close()
				pool.PutBytes(protocol)
				return
			}

			protocol = protocol[:n]

			conn = netapi.NewPrefixBytesConn(conn, protocol)

			switch protocol[0] {
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
