package register

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"reflect"

	"github.com/Asutorufa/yuhaiin/pkg/auth"
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

type CredentialResolver interface {
	ResolveCredential(userID, protocolType string) (auth.ResolvedCredential, error)
}

// ValidateCredentialReferences checks user references without constructing a
// network proxy. It is used by persistence paths so an invalid user ID cannot
// become a dangling node that only fails when first dialed.
func ValidateCredentialReferences(p contractnode.Node, resolver CredentialResolver) error {
	if resolver == nil {
		return nil
	}
	for i := range p.Chain {
		if err := validateProtocolCredential(&p.Chain[i], resolver); err != nil {
			return fmt.Errorf("node %q chain[%d] credentials: %w", p.ID, i, err)
		}
	}
	return nil
}

func validateProtocolCredential(protocol *contractnode.Protocol, resolver CredentialResolver) error {
	if protocol == nil {
		return nil
	}
	resolve := func(userID, typ string) error {
		if userID == "" {
			return nil
		}
		_, err := resolver.ResolveCredential(userID, typ)
		return err
	}
	switch protocol.Type {
	case "shadowsocks":
		if protocol.Shadowsocks == nil {
			return errors.New("shadowsocks protocol config is missing")
		}
		return resolve(protocol.Shadowsocks.UserID, protocol.Type)
	case "shadowsocksr":
		if protocol.Shadowsocksr == nil {
			return errors.New("shadowsocksr protocol config is missing")
		}
		return resolve(protocol.Shadowsocksr.UserID, protocol.Type)
	case "vmess":
		if protocol.Vmess == nil {
			return errors.New("vmess protocol config is missing")
		}
		return resolve(protocol.Vmess.UserID, protocol.Type)
	case "vless":
		if protocol.Vless == nil {
			return errors.New("vless protocol config is missing")
		}
		return resolve(protocol.Vless.UserID, protocol.Type)
	case "trojan":
		if protocol.Trojan == nil {
			return errors.New("trojan protocol config is missing")
		}
		return resolve(protocol.Trojan.UserID, protocol.Type)
	case "socks5":
		if protocol.Socks5 == nil {
			return errors.New("socks5 protocol config is missing")
		}
		return resolve(protocol.Socks5.UserID, protocol.Type)
	case "http":
		if protocol.HTTP == nil {
			return errors.New("http protocol config is missing")
		}
		return resolve(protocol.HTTP.UserID, protocol.Type)
	case "yuubinsya":
		if protocol.Yuubinsya == nil {
			return errors.New("yuubinsya protocol config is missing")
		}
		return resolve(protocol.Yuubinsya.UserID, protocol.Type)
	case "tailscale":
		if protocol.Tailscale == nil {
			return errors.New("tailscale protocol config is missing")
		}
		return resolve(protocol.Tailscale.UserID, protocol.Type)
	case "aead":
		if protocol.AEAD == nil {
			return errors.New("aead protocol config is missing")
		}
		return resolve(protocol.AEAD.UserID, protocol.Type)
	case "network_split":
		if protocol.NetworkSplit == nil {
			return errors.New("network split protocol config is missing")
		}
		if err := validateProtocolCredential(protocol.NetworkSplit.TCP, resolver); err != nil {
			return err
		}
		return validateProtocolCredential(protocol.NetworkSplit.UDP, resolver)
	default:
		return nil
	}
}

// ContractDialerWithAuth keeps credential material out of the persisted node
// contract. The resolver expands a copy immediately before protocol clients
// are constructed; the copy is never written back to SQLite.
func ContractDialerWithAuth(p contractnode.Node, resolver CredentialResolver) (netapi.Proxy, error) {
	if resolver == nil {
		return ContractDialer(p)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("clone node contract: %w", err)
	}
	var resolved contractnode.Node
	if err := json.Unmarshal(data, &resolved); err != nil {
		return nil, fmt.Errorf("clone node contract: %w", err)
	}
	for i := range resolved.Chain {
		if err := resolveProtocolCredentials(&resolved.Chain[i], resolver); err != nil {
			return nil, fmt.Errorf("resolve node %q chain[%d] credentials: %w", resolved.ID, i, err)
		}
	}
	return ContractDialer(resolved)
}

func resolveProtocolCredentials(protocol *contractnode.Protocol, resolver CredentialResolver) error {
	if protocol == nil {
		return nil
	}
	resolve := func(userID, typ string) (auth.ResolvedCredential, error) {
		if userID == "" {
			return auth.ResolvedCredential{}, nil
		}
		return resolver.ResolveCredential(userID, typ)
	}
	switch protocol.Type {
	case "shadowsocks":
		if protocol.Shadowsocks == nil {
			return errors.New("shadowsocks protocol config is missing")
		}
		value, err := resolve(protocol.Shadowsocks.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.Shadowsocks.Password = value.Password
	case "shadowsocksr":
		if protocol.Shadowsocksr == nil {
			return errors.New("shadowsocksr protocol config is missing")
		}
		value, err := resolve(protocol.Shadowsocksr.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.Shadowsocksr.Password = value.Password
	case "vmess":
		if protocol.Vmess == nil {
			return errors.New("vmess protocol config is missing")
		}
		value, err := resolve(protocol.Vmess.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.Vmess.UUID = value.UUID
	case "vless":
		if protocol.Vless == nil {
			return errors.New("vless protocol config is missing")
		}
		value, err := resolve(protocol.Vless.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.Vless.UUID = value.UUID
	case "trojan":
		if protocol.Trojan == nil {
			return errors.New("trojan protocol config is missing")
		}
		value, err := resolve(protocol.Trojan.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.Trojan.Password = value.Password
	case "socks5":
		if protocol.Socks5 == nil {
			return errors.New("socks5 protocol config is missing")
		}
		value, err := resolve(protocol.Socks5.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.Socks5.User, protocol.Socks5.Password = value.Username, value.Password
	case "http":
		if protocol.HTTP == nil {
			return errors.New("http protocol config is missing")
		}
		value, err := resolve(protocol.HTTP.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.HTTP.User, protocol.HTTP.Password = value.Username, value.Password
	case "yuubinsya":
		if protocol.Yuubinsya == nil {
			return errors.New("yuubinsya protocol config is missing")
		}
		value, err := resolve(protocol.Yuubinsya.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.Yuubinsya.Password = value.Password
	case "tailscale":
		if protocol.Tailscale == nil {
			return errors.New("tailscale protocol config is missing")
		}
		value, err := resolve(protocol.Tailscale.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.Tailscale.AuthKey = value.Token
	case "aead":
		if protocol.AEAD == nil {
			return errors.New("aead protocol config is missing")
		}
		value, err := resolve(protocol.AEAD.UserID, protocol.Type)
		if err != nil {
			return err
		}
		protocol.AEAD.Password = value.Password
	case "network_split":
		if protocol.NetworkSplit == nil {
			return errors.New("network split protocol config is missing")
		}
		if protocol.NetworkSplit.TCP != nil {
			if err := resolveProtocolCredentials(protocol.NetworkSplit.TCP, resolver); err != nil {
				return err
			}
		}
		if protocol.NetworkSplit.UDP != nil {
			if err := resolveProtocolCredentials(protocol.NetworkSplit.UDP, resolver); err != nil {
				return err
			}
		}
	}
	return nil
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
