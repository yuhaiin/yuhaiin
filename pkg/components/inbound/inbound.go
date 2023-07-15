package inbound

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	httpproxy "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

func init() {
	pl.RegisterProtocol(httpproxy.NewServer)
	pl.RegisterProtocol(ss.NewServer)
	pl.RegisterProtocol(tun.NewTun)
	pl.RegisterProtocol(func(o *pl.Opts[*pl.Protocol_Yuubinsya]) (proxy.Server, error) {
		var Type yuubinsya.Type
		var err error
		var tlsConfig *tls.Config
		switch p := o.Protocol.Yuubinsya.Protocol.(type) {
		case *pl.Yuubinsya_Normal:
			Type = yuubinsya.RAW_TCP
		case *pl.Yuubinsya_Tls:
			Type = yuubinsya.TLS
			tlsConfig, err = pl.ParseTLS(p.Tls.GetTls())
		case *pl.Yuubinsya_Quic:
			Type = yuubinsya.QUIC
			tlsConfig, err = pl.ParseTLS(p.Quic.GetTls())
		case *pl.Yuubinsya_Websocket:
			Type = yuubinsya.WEBSOCKET
			tlsConfig, err = pl.ParseTLS(p.Websocket.GetTls())
		case *pl.Yuubinsya_Grpc:
			Type = yuubinsya.GRPC
			tlsConfig, err = pl.ParseTLS(p.Grpc.GetTls())
		case *pl.Yuubinsya_Http2:
			Type = yuubinsya.HTTP2
			tlsConfig, err = pl.ParseTLS(p.Http2.GetTls())

		}
		if err != nil {
			return nil, err
		}

		s := yuubinsya.NewServer(yuubinsya.Config{
			Host:                o.Protocol.Yuubinsya.Host,
			Password:            []byte(o.Protocol.Yuubinsya.Password),
			TlsConfig:           tlsConfig,
			Type:                Type,
			ForceDisableEncrypt: o.Protocol.Yuubinsya.ForceDisableEncrypt,
			Handler:             o.Handler,
		})
		go s.Start()
		return s, nil
	})
}

type store struct {
	config proto.Message
	server proxy.Server
}
type listener struct {
	store syncmap.SyncMap[string, store]
	opts  *pl.Opts[pl.IsProtocol_Protocol]
}

func NewListener(dnsHandler proxy.DNSHandler, handler proxy.Handler) *listener {
	return &listener{opts: &pl.Opts[pl.IsProtocol_Protocol]{
		DNSHandler: dnsHandler,
		Handler:    handler,
	}}
}

func (l *listener) Update(current *pc.Setting) {
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
			if errors.Is(err, errServerDisabled) {
				log.Debug(err.Error())
			} else {
				log.Error(fmt.Sprintf("start %s failed", k), "err", err)
			}
		}
	}
}

var errServerDisabled = errors.New("disabled")

func (l *listener) start(name string, config *pl.Protocol) error {
	v, ok := l.store.Load(name)
	if ok {
		if proto.Equal(v.config, config) {
			return nil
		}
		v.server.Close()
		l.store.Delete(name)
	}

	if !config.Enabled {
		return fmt.Errorf("server %s %w", config.Name, errServerDisabled)
	}

	server, err := pl.CreateServer(pl.CovertOpts(l.opts, func(pl.IsProtocol_Protocol) pl.IsProtocol_Protocol { return config.Protocol }))
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
