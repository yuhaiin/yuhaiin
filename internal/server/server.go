package server

import (
	"io"
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	hs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	rs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

type listener struct {
	lock  sync.Mutex
	store map[string]struct {
		hash   string
		server proxy.Server
	}
}

func init() {
	protoconfig.RegisterProtocol(func(p *protoconfig.ServerProtocol_Http, dialer proxy.Proxy) (proxy.Server, error) {
		return hs.NewServer(p.Http.Host, p.Http.Username, p.Http.Password, dialer)
	})
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Socks5, dialer proxy.Proxy) (proxy.Server, error) {
		return ss.NewServer(t.Socks5.Host, t.Socks5.Username, t.Socks5.Password, dialer)
	})
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Redir, dialer proxy.Proxy) (proxy.Server, error) {
		return rs.NewServer(t.Redir.Host, dialer)
	})
}

func NewListener(c config.ConfigObserver, pro proxy.Proxy) io.Closer {
	if pro == nil {
		pro = &proxy.Default{}
	}
	l := &listener{
		store: make(map[string]struct {
			hash   string
			server proxy.Server
		}),
	}

	c.AddObserverAndExec(func(_, _ *protoconfig.Setting) bool { return true }, func(current *protoconfig.Setting) {
		l.lock.Lock()
		defer l.lock.Unlock()
		for k, v := range l.store {
			if _, ok := current.Server.Servers[k]; !ok {
				v.server.Close()
				delete(l.store, k)
			}
		}

		for k, v := range current.Server.Servers {
			l.update(k, pro, v)
		}
	})

	return l
}

func (l *listener) update(name string, pro proxy.Proxy, config *protoconfig.ServerProtocol) {
	v, ok := l.store[name]
	if !ok {
		l.start(name, pro, config)
		return
	}

	if v.hash == config.Hash {
		return
	}

	v.server.Close()
	delete(l.store, name)

	l.start(name, pro, config)
}

func (l *listener) start(name string, pro proxy.Proxy, config *protoconfig.ServerProtocol) {
	server, err := protoconfig.CreateServer(config.Protocol, pro)
	if err != nil {
		logasfmt.Printf("create server %s failed: %v\n", name, err)
		return
	}

	l.store[name] = struct {
		hash   string
		server proxy.Server
	}{
		hash:   config.Hash,
		server: server,
	}
}

func (l *listener) Close() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	for _, v := range l.store {
		v.server.Close()
	}

	l.store = make(map[string]struct {
		hash   string
		server proxy.Server
	})

	return nil
}
