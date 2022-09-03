package server

import (
	"fmt"
	"log"

	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	hs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/server"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

func init() {
	protoconfig.RegisterProtocol(hs.NewServer)
	protoconfig.RegisterProtocol(ss.NewServer)
	protoconfig.RegisterProtocol(tun.NewTun)
}

type store struct {
	config proto.Message
	server iserver.Server
}
type listener struct {
	store syncmap.SyncMap[string, store]
	opts  *protoconfig.Opts[protoconfig.IsServerProtocol_Protocol]
}

func NewListener(opts *protoconfig.Opts[protoconfig.IsServerProtocol_Protocol]) *listener {
	if opts.Dialer == nil {
		opts.Dialer = direct.Default
	}
	return &listener{opts: opts}
}

func (l *listener) Update(current *protoconfig.Setting) {
	l.opts.IPv6 = current.Ipv6

	l.store.Range(func(key string, v store) bool {
		z, ok := current.Server.Servers[key]
		if !ok || !z.GetEnabled() {
			v.server.Close()
			l.store.Delete(key)
		}

		return true
	})

	for k, v := range current.Server.Servers {
		if err := l.start(k, v); err != nil {
			log.Println(err)
		}
	}
}

func (l *listener) start(name string, config *protoconfig.ServerProtocol) error {
	v, ok := l.store.Load(name)
	if ok {
		if proto.Equal(v.config, config) {
			return nil
		}
		v.server.Close()
		l.store.Delete(name)
	}

	if !config.Enabled {
		return fmt.Errorf("server %s disabled", config.Name)
	}

	server, err := protoconfig.CreateServer(
		protoconfig.CovertOpts(l.opts, func(protoconfig.IsServerProtocol_Protocol) protoconfig.IsServerProtocol_Protocol {
			return config.Protocol
		}))
	if err != nil {
		return fmt.Errorf("create server %s failed: %w", name, err)
	}

	l.store.Store(name, store{config, server})
	return nil
}

func (l *listener) Close() error {
	l.store.Range(func(key string, value store) bool {
		value.server.Close()
		l.store.Delete(key)
		return true
	})
	return nil
}
