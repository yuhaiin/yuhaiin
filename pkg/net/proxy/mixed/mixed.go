package mixed

import (
	"bufio"
	"context"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type Mixed struct {
	lis      net.Listener
	defaultC *netapi.ChannelStreamListener
	mchs     []*Matcher
	closers  []io.Closer
}

type Matcher struct {
	match func(byte) bool
	ch    *netapi.ChannelStreamListener
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
			lis:      lis,
			defaultC: netapi.NewChannelStreamListener(lis.Addr()),
		}

		mix.socks5(o, ii, handler)
		mix.socks4(o, ii, handler)
		mix.http(o, ii, handler)

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
	m.defaultC.Close()

	for _, c := range m.mchs {
		c.ch.Close()
	}

	for _, c := range m.closers {
		c.Close()
	}
	return m.lis.Close()
}

func (m *Mixed) AddMatcher(match func(byte) bool) net.Listener {
	ch := netapi.NewChannelStreamListener(m.lis.Addr())
	m.mchs = append(m.mchs, &Matcher{
		match: match,
		ch:    ch,
	})
	return ch
}

func (m *Mixed) socks5(o *listener.Inbound_Mix, ii netapi.Listener, handler netapi.Handler) {
	lis := m.AddMatcher(func(b byte) bool { return b == 0x05 })

	s5, err := socks5.NewServer(&listener.Inbound_Socks5{
		Socks5: &listener.Socks5{
			Username: o.Mix.Username,
			Password: o.Mix.Password,
			Udp:      true,
		},
	})(netapi.NewListener(lis, ii), handler)
	if err != nil {
		log.Error("new socks5 server failed", "err", err)
		return
	}

	m.closers = append(m.closers, s5)
}

func (m *Mixed) socks4(o *listener.Inbound_Mix, ii netapi.Listener, handler netapi.Handler) {
	lis := m.AddMatcher(func(b byte) bool { return b == 0x04 })

	s4, err := socks4a.NewServer(&listener.Inbound_Socks4A{
		Socks4A: &listener.Socks4A{
			Username: o.Mix.Username,
		},
	})(netapi.NewListener(lis, ii), handler)
	if err != nil {
		log.Error("new socks4 server failed", "err", err)
		return
	}

	m.closers = append(m.closers, s4)
}

func (m *Mixed) http(o *listener.Inbound_Mix, ii netapi.Listener, handler netapi.Handler) {
	http, err := http.NewServer(&listener.Inbound_Http{
		Http: &listener.Http{
			Username: o.Mix.Username,
			Password: o.Mix.Password,
		},
	})(netapi.NewListener(m.defaultC, ii), handler)
	if err != nil {
		log.Error("new http server failed", "err", err)
		return
	}

	m.closers = append(m.closers, http)
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
				_ = conn.SetReadDeadline(time.Now().Add(time.Second * 10))
				protocol, err = r.ReadByte()
				_ = conn.SetReadDeadline(time.Time{})
				if err == nil {
					_ = r.UnreadByte()
				}
				return err
			})
			if err != nil {
				_ = conn.Close()
				log.Error("peek protocol failed", "err", err)
				return
			}

			for _, matcher := range m.mchs {
				if matcher.match(protocol) {
					matcher.ch.NewConn(conn)
					return
				}
			}

			m.defaultC.NewConn(conn)
		}()
	}
}
