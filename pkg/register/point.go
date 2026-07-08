package register

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func GetPointValue(i *node.Protocol) any {
	if i == nil {
		return &node.None{}
	}
	switch i.WhichProtocol() {
	case node.Protocol_Shadowsocks_case:
		return i.GetShadowsocks()
	case node.Protocol_Shadowsocksr_case:
		return i.GetShadowsocksr()
	case node.Protocol_Vmess_case:
		return i.GetVmess()
	case node.Protocol_Websocket_case:
		return i.GetWebsocket()
	case node.Protocol_Quic_case:
		return i.GetQuic()
	case node.Protocol_ObfsHttp_case:
		return i.GetObfsHttp()
	case node.Protocol_Trojan_case:
		return i.GetTrojan()
	case node.Protocol_Simple_case:
		return i.GetSimple()
	case node.Protocol_Socks5_case:
		return i.GetSocks5()
	case node.Protocol_Http_case:
		return i.GetHttp()
	case node.Protocol_Direct_case:
		return i.GetDirect()
	case node.Protocol_Reject_case:
		return i.GetReject()
	case node.Protocol_Yuubinsya_case:
		return i.GetYuubinsya()
	case node.Protocol_Http2_case:
		return i.GetHttp2()
	case node.Protocol_Reality_case:
		return i.GetReality()
	case node.Protocol_Tls_case:
		return i.GetTls()
	case node.Protocol_Wireguard_case:
		return i.GetWireguard()
	case node.Protocol_Mux_case:
		return i.GetMux()
	case node.Protocol_Drop_case:
		return i.GetDrop()
	case node.Protocol_Vless_case:
		return i.GetVless()
	case node.Protocol_BootstrapDnsWarp_case:
		return i.GetBootstrapDnsWarp()
	case node.Protocol_Tailscale_case:
		return i.GetTailscale()
	case node.Protocol_Set_case:
		return i.GetSet()
	case node.Protocol_TlsTermination_case:
		return i.GetTlsTermination()
	case node.Protocol_HttpTermination_case:
		return i.GetHttpTermination()
	case node.Protocol_HttpMock_case:
		return i.GetHttpMock()
	case node.Protocol_Aead_case:
		return i.GetAead()
	case node.Protocol_Fixed_case:
		return i.GetFixed()
	case node.Protocol_NetworkSplit_case:
		return i.GetNetworkSplit()
	case node.Protocol_CloudflareWarpMasque_case:
		return i.GetCloudflareWarpMasque()
	case node.Protocol_Proxy_case:
		return i.GetProxy()
	case node.Protocol_Fixedv2_case:
		return i.GetFixedv2()
	case node.Protocol_PointAsEndpoint_case:
		return i.GetPointAsEndpoint()
	default:
		return &node.None{}
	}
}

func init() {
	RegisterPoint(func(_ *node.None, p netapi.Proxy) (netapi.Proxy, error) {
		return p, nil
	})
	RegisterPoint(func(_ *node.BootstrapDnsWarp, p netapi.Proxy) (netapi.Proxy, error) {
		return NewBootstrapDnsWarp(p), nil
	})

	RegisterPoint(func(ns *node.NetworkSplit, p netapi.Proxy) (netapi.Proxy, error) {
		if ns.GetTcp().WhichProtocol() == node.Protocol_NetworkSplit_case {
			return nil, fmt.Errorf("nested network split is not supported")
		}

		if ns.GetUdp().WhichProtocol() == node.Protocol_NetworkSplit_case {
			return nil, fmt.Errorf("nested network split is not supported")
		}

		tcp, err := Wrap(GetPointValue(ns.GetTcp()), p)
		if err != nil {
			return nil, err
		}

		udp, err := Wrap(GetPointValue(ns.GetUdp()), p)
		if err != nil {
			_ = tcp.Close()
			return nil, err
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

func Dialer(p *node.Point) (r netapi.Proxy, err error) {
	r = zeroproxy

	for _, v := range p.GetProtocols() {
		r, err = Wrap(GetPointValue(v), r)
		if err != nil {
			return
		}
	}

	return
}

type WrapProxy[T any] func(t T, p netapi.Proxy) (netapi.Proxy, error)

var execProtocol syncmap.SyncMap[reflect.Type, func(any, netapi.Proxy) (netapi.Proxy, error)]

func RegisterPoint[T any](wrap func(T, netapi.Proxy) (netapi.Proxy, error)) {
	if wrap == nil {
		return
	}

	execProtocol.Store(
		reflect.TypeOf((*T)(nil)).Elem(),
		func(t any, p netapi.Proxy) (netapi.Proxy, error) { return wrap(t.(T), p) },
	)
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
