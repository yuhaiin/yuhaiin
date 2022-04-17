package app

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

type Listener struct {
	lock  sync.Mutex
	store map[string]struct {
		hash   string
		server proxy.Server
	}
}

func init() {
	protoconfig.RegisterProtocol(func(p *protoconfig.ServerProtocol_Http) (proxy.Server, error) {
		return hs.NewServer(p.Http.Host, p.Http.Username, p.Http.Password)
	})
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Socks5) (proxy.Server, error) {
		return ss.NewServer(t.Socks5.Host, t.Socks5.Username, t.Socks5.Password)
	})
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Redir) (proxy.Server, error) {
		return rs.NewServer(t.Redir.Host)
	})
}

func NewListener(c *config.Config, pro proxy.Proxy) io.Closer {
	if pro == nil {
		pro = &proxy.Default{}
	}
	l := &Listener{
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

func (l *Listener) update(name string, pro proxy.Proxy, config *protoconfig.ServerProtocol) {
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

func (l *Listener) start(name string, pro proxy.Proxy, config *protoconfig.ServerProtocol) {
	server, err := protoconfig.CreateServer(config.Protocol)
	if err != nil {
		logasfmt.Printf("create server failed: %v\n", err)
		return
	}

	server.SetProxy(pro)
	l.store[name] = struct {
		hash   string
		server proxy.Server
	}{
		hash:   config.Hash,
		server: server,
	}
}

func (l *Listener) Close() error {
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
