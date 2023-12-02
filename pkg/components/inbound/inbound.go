package inbound

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/grpc"
	hp "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/mixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks4a"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

func init() {
	pl.RegisterProtocol(hp.NewServer)
	pl.RegisterProtocol(func(o *pl.Opts[*pl.Protocol_Socks5]) (netapi.Server, error) { return ss.NewServer(o, true) })
	pl.RegisterProtocol(mixed.NewServer)
	pl.RegisterProtocol(socks4a.NewServer)
	pl.RegisterProtocol(tun.NewTun)
	pl.RegisterProtocol(func(o *pl.Opts[*pl.Protocol_Yuubinsya]) (netapi.Server, error) {
		var Type yuubinsya.Type
		var err error
		var tlsConfig *tls.Config
		var listener func(net.Listener) (net.Listener, error)
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
			listener = func(l net.Listener) (net.Listener, error) { return websocket.NewServer(l), nil }
			tlsConfig, err = pl.ParseTLS(p.Websocket.GetTls())
		case *pl.Yuubinsya_Grpc:
			Type = yuubinsya.GRPC
			listener = func(l net.Listener) (net.Listener, error) { return grpc.NewServer(l), nil }
			tlsConfig, err = pl.ParseTLS(p.Grpc.GetTls())
		case *pl.Yuubinsya_Http2:
			Type = yuubinsya.HTTP2
			listener = func(l net.Listener) (net.Listener, error) { return http2.NewServer(l), nil }
			tlsConfig, err = pl.ParseTLS(p.Http2.GetTls())
		case *pl.Yuubinsya_Reality:
			Type = yuubinsya.REALITY
			privateKey, er := base64.RawURLEncoding.DecodeString(p.Reality.PrivateKey)
			if er != nil {
				err = er
				break
			}

			listener = func(l net.Listener) (net.Listener, error) {
				return reality.NewServer(l, reality.ServerConfig{
					ShortID:     p.Reality.ShortId,
					ServerNames: p.Reality.ServerName,
					Dest:        p.Reality.Dest,
					PrivateKey:  privateKey,
					Debug:       p.Reality.Debug,
				})
			}
		}
		if err != nil {
			return nil, err
		}

		if o.Protocol.Yuubinsya.Mux {
			old := listener
			listener = func(l net.Listener) (net.Listener, error) {
				if old != nil {
					l, err = old(l)
					if err != nil {
						return nil, err
					}
				}

				return http2.NewServer(l), nil
			}
		}

		s := yuubinsya.NewServer(yuubinsya.Config{
			Host:                o.Protocol.Yuubinsya.Host,
			Password:            []byte(o.Protocol.Yuubinsya.Password),
			TlsConfig:           tlsConfig,
			Type:                Type,
			ForceDisableEncrypt: o.Protocol.Yuubinsya.ForceDisableEncrypt,
			Handler:             o.Handler,
			NewListener:         listener,
		})
		go s.Start() //nolint:errcheck
		return s, nil
	})
}

type store struct {
	config proto.Message
	server netapi.Server
}

type listener struct {
	store syncmap.SyncMap[string, store]
	opts  *pl.Opts[pl.IsProtocol_Protocol]
}

func NewListener(dnsHandler netapi.DNSHandler, handler netapi.Handler) *listener {
	return &listener{opts: &pl.Opts[pl.IsProtocol_Protocol]{
		DNSHandler: dnsHandler,
		Handler:    handler,
	}}
}

func (l *listener) Update(current *pc.Setting) {
	l.opts.IPv6 = current.GetIpv6()

	l.store.Range(func(key string, v store) bool {
		if z, ok := current.Server.Servers[key]; !ok || !z.GetEnabled() {
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
