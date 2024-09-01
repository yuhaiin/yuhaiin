package mixed

import (
	"bufio"
	"context"
	"io"
	"log/slog"
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

	s5c *netapi.ChannelStreamListener
	s5  netapi.Accepter

	s4c *netapi.ChannelStreamListener
	s4  netapi.Accepter

	httpc *netapi.ChannelStreamListener
	http  netapi.Accepter
}

func init() {
	listener.RegisterProtocol(NewServer)
}

func NewServer(o *listener.Inbound_Mix) func(lis netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	return func(ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
		lis, err := ii.Stream(context.TODO())
		if err != nil {
			return nil, err
		}

		mix := &Mixed{
			lis: lis,
		}

		mix.s5c = netapi.NewChannelStreamListener(lis.Addr())
		mix.s5, err = socks5.NewServer(&listener.Inbound_Socks5{
			Socks5: &listener.Socks5{
				Username: o.Mix.Username,
				Password: o.Mix.Password,
				Udp:      true,
			},
		})(netapi.NewListener(mix.s5c, ii), handler)
		if err != nil {
			mix.Close()
			return nil, err
		}

		mix.s4c = netapi.NewChannelStreamListener(lis.Addr())
		mix.s4, err = socks4a.NewServer(&listener.Inbound_Socks4A{
			Socks4A: &listener.Socks4A{
				Username: o.Mix.Username,
			},
		})(netapi.NewListener(mix.s4c, ii), handler)
		if err != nil {
			mix.Close()
			return nil, err
		}

		mix.httpc = netapi.NewChannelStreamListener(lis.Addr())
		mix.http, err = http.NewServer(&listener.Inbound_Http{
			Http: &listener.Http{
				Username: o.Mix.Username,
				Password: o.Mix.Password,
			},
		})(netapi.NewListener(mix.httpc, ii), handler)
		if err != nil {
			mix.Close()
			return nil, err
		}

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
	noneNilClose(m.s5c)
	noneNilClose(m.s5)
	noneNilClose(m.s4c)
	noneNilClose(m.s4)
	noneNilClose(m.httpc)
	noneNilClose(m.http)
	return m.lis.Close()
}

func noneNilClose(i io.Closer) {
	if c, ok := i.(*netapi.ChannelStreamListener); ok {
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
			conn := pool.NewBufioConnSize(conn, pool.DefaultSize)

			var protocol byte
			err := conn.BufioRead(func(r *bufio.Reader) error {
				protocol, err = r.ReadByte()
				if err == nil {
					_ = r.UnreadByte()
				}
				return err
			})
			if err != nil {
				_ = conn.Close()
				slog.Error("peek protocol failed", "err", err)
				return
			}

			switch protocol {
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
