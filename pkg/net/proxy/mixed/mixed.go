package mixed

import (
	"bufio"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type Mixed struct {
	netapi.EmptyInterface
	lis      net.Listener
	defaultC *netapi.ChannelStreamListener
	mchs     []*Matcher
	closers  []io.Closer
}

type Matcher struct {
	match func(byte) bool
	ch    *netapi.ChannelStreamListener
}

type ServerConfig struct {
	Username string `json:"username,omitzero"`
	Password string `json:"password,omitzero"`
}

func NewServer(o ServerConfig, ii netapi.Listener, handler netapi.Handler) (netapi.Accepter, error) {
	mix := &Mixed{
		lis:      ii,
		defaultC: netapi.NewChannelStreamListener(ii.Addr()),
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

func (m *Mixed) socks5(o ServerConfig, ii netapi.Listener, handler netapi.Handler) {
	lis := m.AddMatcher(func(b byte) bool { return b == 0x05 })

	s5, err := socks5.NewServer(socks5.ServerConfig{
		Username: o.Username,
		Password: o.Password,
		UDP:      true,
	}, netapi.NewListener(lis, ii), handler)
	if err != nil {
		log.Error("new socks5 server failed", "err", err)
		return
	}

	m.closers = append(m.closers, s5)
}

func (m *Mixed) socks4(o ServerConfig, ii netapi.Listener, handler netapi.Handler) {
	lis := m.AddMatcher(func(b byte) bool { return b == 0x04 })

	s4, err := socks4a.NewServer(socks4a.ServerConfig{
		Username: o.Username,
	}, netapi.NewListener(lis, ii), handler)
	if err != nil {
		log.Error("new socks4 server failed", "err", err)
		return
	}

	m.closers = append(m.closers, s4)
}

func (m *Mixed) http(o ServerConfig, ii netapi.Listener, handler netapi.Handler) {
	http, err := http.NewServer(http.ServerConfig{
		Username: o.Username,
		Password: o.Password,
	}, netapi.NewListener(m.defaultC, ii), handler)
	if err != nil {
		log.Error("new http server failed", "err", err)
		return
	}

	m.closers = append(m.closers, http)
}

func (m *Mixed) handle() error {
	ml := netapi.NewErrCountListener(m.lis, 10)

	for {
		conn, err := ml.Accept()
		if err != nil {
			log.Error("mixed accept failed", "err", err)

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}

		go func() {
			conn := pool.NewBufioConnSize(conn, configuration.UDPBufferSize.Load())

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
