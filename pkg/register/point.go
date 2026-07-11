package register

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func init() {
	RegisterContractPoint("none", func(_ contractnode.None, p netapi.Proxy) (netapi.Proxy, error) {
		return p, nil
	})
	RegisterContractPoint("bootstrap_dns_warp", func(_ contractnode.BootstrapDNSWarp, p netapi.Proxy) (netapi.Proxy, error) {
		return NewBootstrapDnsWarp(p), nil
	})
	RegisterContractPoint("network_split", func(config contractnode.NetworkSplit, p netapi.Proxy) (netapi.Proxy, error) {
		if config.TCP == nil && config.UDP == nil {
			return nil, errors.New("network split protocols are empty")
		}
		if (config.TCP != nil && config.TCP.Type == "network_split") || (config.UDP != nil && config.UDP.Type == "network_split") {
			return nil, errors.New("nested network split is not supported")
		}

		tcp := p
		if config.TCP != nil {
			var err error
			tcp, err = ContractWrap(*config.TCP, p)
			if err != nil {
				return nil, err
			}
		}
		udp := p
		if config.UDP != nil {
			var err error
			udp, err = ContractWrap(*config.UDP, p)
			if err != nil {
				if config.TCP != nil {
					_ = tcp.Close()
				}
				return nil, err
			}
		}
		return &networkSplit{tcp: tcp, udp: udp, Proxy: p}, nil
	})
}

var _ netapi.Proxy = (*networkSplit)(nil)

type networkSplit struct {
	tcp netapi.Proxy
	udp netapi.Proxy
	netapi.Proxy
}

func (n *networkSplit) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return n.tcp.Conn(ctx, addr)
}

func (n *networkSplit) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return n.udp.PacketConn(ctx, addr)
}

func (n *networkSplit) Close() error {
	var err error
	if er := n.tcp.Close(); er != nil {
		err = errors.Join(err, er)
	}
	if er := n.udp.Close(); er != nil {
		err = errors.Join(err, er)
	}
	if er := n.Proxy.Close(); er != nil {
		err = errors.Join(err, er)
	}
	return err
}

func ContractDialer(p contractnode.Node) (r netapi.Proxy, err error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	r = zeroproxy
	for i, protocol := range p.Chain {
		r, err = ContractWrap(protocol, r)
		if err != nil {
			return nil, fmt.Errorf("contract node %q chain[%d]: %w", p.ID, i, err)
		}
	}
	return r, nil
}

func ContractWrap(protocol contractnode.Protocol, p netapi.Proxy) (netapi.Proxy, error) {
	if err := protocol.Validate(); err != nil {
		return nil, err
	}
	if fn, ok := execContractProtocol.Load(protocol.Type); ok {
		obj, err := ContractProtocolConfig(protocol)
		if err != nil {
			return nil, err
		}
		return fn(obj, p)
	}
	return nil, fmt.Errorf("node protocol %q is not registered", protocol.Type)
}

func ContractProtocolConfig(protocol contractnode.Protocol) (any, error) {
	if err := protocol.Validate(); err != nil {
		return nil, err
	}
	switch protocol.Type {
	case "shadowsocks":
		return *protocol.Shadowsocks, nil
	case "shadowsocksr":
		return *protocol.Shadowsocksr, nil
	case "vmess":
		return *protocol.Vmess, nil
	case "websocket":
		return *protocol.Websocket, nil
	case "quic":
		return *protocol.Quic, nil
	case "obfs_http":
		return *protocol.ObfsHTTP, nil
	case "trojan":
		return *protocol.Trojan, nil
	case "simple":
		return *protocol.Simple, nil
	case "none":
		return *protocol.None, nil
	case "socks5":
		return *protocol.Socks5, nil
	case "http":
		return *protocol.HTTP, nil
	case "direct":
		return *protocol.Direct, nil
	case "reject":
		return *protocol.Reject, nil
	case "yuubinsya":
		return *protocol.Yuubinsya, nil
	case "http2":
		return *protocol.HTTP2, nil
	case "reality":
		return *protocol.Reality, nil
	case "tls":
		return *protocol.TLS, nil
	case "wireguard":
		return *protocol.Wireguard, nil
	case "mux":
		return *protocol.Mux, nil
	case "drop":
		return *protocol.Drop, nil
	case "vless":
		return *protocol.Vless, nil
	case "bootstrap_dns_warp":
		return *protocol.BootstrapDNSWarp, nil
	case "tailscale":
		return *protocol.Tailscale, nil
	case "set":
		return *protocol.Set, nil
	case "tls_termination":
		return *protocol.TLSTermination, nil
	case "http_termination":
		return *protocol.HTTPTermination, nil
	case "http_mock":
		return *protocol.HTTPMock, nil
	case "aead":
		return *protocol.AEAD, nil
	case "fixed":
		return *protocol.Fixed, nil
	case "network_split":
		return *protocol.NetworkSplit, nil
	case "cloudflare_warp_masque":
		return *protocol.CloudflareWarpMasque, nil
	case "proxy":
		return *protocol.Proxy, nil
	case "fixedv2":
		return *protocol.FixedV2, nil
	case "point_as_endpoint":
		return *protocol.PointAsEndpoint, nil
	default:
		return nil, fmt.Errorf("unknown node protocol type %q", protocol.Type)
	}
}

type WrapProxy[T any] func(t T, p netapi.Proxy) (netapi.Proxy, error)

var execProtocol syncmap.SyncMap[reflect.Type, func(any, netapi.Proxy) (netapi.Proxy, error)]
var execContractProtocol syncmap.SyncMap[string, func(any, netapi.Proxy) (netapi.Proxy, error)]

func RegisterPoint[T any](wrap func(T, netapi.Proxy) (netapi.Proxy, error)) {
	if wrap == nil {
		return
	}

	execProtocol.Store(
		reflect.TypeFor[T](),
		func(t any, p netapi.Proxy) (netapi.Proxy, error) { return wrap(t.(T), p) },
	)
}

func RegisterContractPoint[T any](typ string, wrap func(T, netapi.Proxy) (netapi.Proxy, error)) {
	if typ == "" || wrap == nil {
		return
	}
	execContractProtocol.Store(typ, func(config any, p netapi.Proxy) (netapi.Proxy, error) {
		typed, ok := config.(T)
		if !ok {
			return nil, fmt.Errorf("node protocol %q config type %T does not match registered type %s", typ, config, reflect.TypeFor[T]())
		}
		return wrap(typed, p)
	})
}

func Wrap(p any, x netapi.Proxy) (netapi.Proxy, error) {
	if p == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	conn, ok := execProtocol.Load(reflect.TypeOf(p))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", p)
	}

	return conn(p, x)
}

var zeroproxy = netapi.NewErrProxy(errors.New("bootstrap proxy"))

func IsZero(p netapi.Proxy) bool { return p == zeroproxy }

func SetBootstrap(p netapi.Proxy) {
	if p == nil {
		return
	}

	zeroproxy = p
}

type bootstrapDnsWarp struct {
	netapi.Proxy
}

func NewBootstrapDnsWarp(p netapi.Proxy) netapi.Proxy {
	return &bootstrapDnsWarp{Proxy: p}
}

func (b *bootstrapDnsWarp) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return b.Proxy.Conn(netapi.WithContext(ctx), addr)
}

func (b *bootstrapDnsWarp) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return b.Proxy.PacketConn(netapi.WithContext(ctx), addr)
}
