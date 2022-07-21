package server

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	hs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/server"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

func init() {
	protoconfig.RegisterProtocol(func(p *protoconfig.ServerProtocol_Http, opts ...func(*protoconfig.Opts)) (iserver.Server, error) {
		if !p.Http.Enabled {
			return nil, fmt.Errorf("http server is disabled")
		}
		x := &protoconfig.Opts{Dialer: proxy.NewErrProxy(errors.New("not implemented"))}
		for _, o := range opts {
			o(x)
		}
		return hs.NewServer(p.Http.Host, p.Http.Username, p.Http.Password, x.Dialer)
	})
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Socks5, opts ...func(*protoconfig.Opts)) (iserver.Server, error) {
		if !t.Socks5.Enabled {
			return nil, fmt.Errorf("socks5 server is disabled")
		}
		x := &protoconfig.Opts{Dialer: proxy.NewErrProxy(errors.New("not implemented"))}
		for _, o := range opts {
			o(x)
		}
		return ss.NewServer(t.Socks5.Host, t.Socks5.Username, t.Socks5.Password, x.Dialer)
	})
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Tun, opts ...func(*protoconfig.Opts)) (iserver.Server, error) {
		if !t.Tun.Enabled {
			return nil, fmt.Errorf("tun server is disabled")
		}
		x := &protoconfig.Opts{Dialer: proxy.NewErrProxy(errors.New("not implemented"))}
		for _, o := range opts {
			o(x)
		}
		return tun.NewTun(&tun.TunOpt{
			Name:           t.Tun.Name,
			MTU:            int(t.Tun.Mtu),
			Gateway:        t.Tun.Gateway,
			DNSHijacking:   t.Tun.DnsHijacking,
			Dialer:         x.Dialer,
			DNS:            x.DNSServer,
			EndpointDriver: t.Tun.Driver,
			SkipMulticast:  t.Tun.SkipMulticast,
			UidDumper:      x.UidDumper,
			IPv6:           x.IPv6,
		})
	})
}

type listener struct {
	lock  sync.Mutex
	store map[string]struct {
		config proto.Message
		server iserver.Server
	}

	opts *protoconfig.Opts
}

func NewListener(opts *protoconfig.Opts) *listener {
	if opts.Dialer == nil {
		opts.Dialer = direct.Default
	}
	l := &listener{
		store: make(map[string]struct {
			config proto.Message
			server iserver.Server
		}),
		opts: opts,
	}

	return l
}

func (l *listener) Update(current *protoconfig.Setting) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.opts.IPv6 = current.Ipv6
	for k, v := range l.store {
		z, ok := current.Server.Servers[k]
		if ok {
			en, o := z.GetProtocol().(interface{ GetEnabled() bool })
			if o && !en.GetEnabled() {
				ok = false
			}
		}

		if !ok {
			v.server.Close()
			delete(l.store, k)
		}
	}

	for k, v := range current.Server.Servers {
		l.update(k, v)
	}
}

func (l *listener) update(name string, config *protoconfig.ServerProtocol) {
	v, ok := l.store[name]
	if !ok {
		l.start(name, config)
		return
	}

	if proto.Equal(v.config, config) {
		return
	}

	v.server.Close()
	delete(l.store, name)

	l.start(name, config)
}

func (l *listener) start(name string, config *protoconfig.ServerProtocol) {
	server, err := protoconfig.CreateServer(
		config.Protocol,
		func(o *protoconfig.Opts) { *o = *l.opts },
	)
	if err != nil {
		log.Printf("create server %s failed: %v\n", name, err)
		return
	}

	l.store[name] = struct {
		config proto.Message
		server iserver.Server
	}{
		config: config,
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
		config proto.Message
		server iserver.Server
	})

	return nil
}
