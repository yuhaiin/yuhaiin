package route

import (
	"strconv"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type Mode string

const (
	ModeBypass Mode = "bypass"
	ModeProxy  Mode = "proxy"
	ModeDirect Mode = "direct"
	ModeBlock  Mode = "block"
)

func (m Mode) String() string { return string(m) }

func (m Mode) Unspecified() bool { return m == "" || m == ModeBypass }

type ResolveStrategy string

const (
	ResolveDefault    ResolveStrategy = "default"
	ResolveOnlyIPv4   ResolveStrategy = "only_ipv4"
	ResolvePreferIPv4 ResolveStrategy = "prefer_ipv4"
	ResolveOnlyIPv6   ResolveStrategy = "only_ipv6"
	ResolvePreferIPv6 ResolveStrategy = "prefer_ipv6"
)

type UDPProxyFQDNStrategy string

const (
	UDPProxyFQDNDefault     UDPProxyFQDNStrategy = "default"
	UDPProxyFQDNResolve     UDPProxyFQDNStrategy = "resolve"
	UDPProxyFQDNSkipResolve UDPProxyFQDNStrategy = "skip_resolve"
)

type ModeEnum struct {
	Tag                  string
	resolver             string
	mode                 Mode
	resolveStrategy      ResolveStrategy
	udpProxyFQDNStrategy UDPProxyFQDNStrategy
}

func (m ModeEnum) Mode() Mode                              { return m.mode }
func (m ModeEnum) GetTag() string                          { return m.Tag }
func (m ModeEnum) GetResolveStrategy() ResolveStrategy     { return m.resolveStrategy }
func (m ModeEnum) UdpProxyFqdn() UDPProxyFQDNStrategy      { return m.udpProxyFQDNStrategy }
func (m ModeEnum) Resolver() string                        { return m.resolver }
func (m ModeEnum) WithResolver(resolver string) ModeEnum   { m.resolver = resolver; return m }
func (m ModeEnum) WithTag(tag string) ModeEnum             { m.Tag = tag; return m }
func (m ModeEnum) WithResolve(s ResolveStrategy) ModeEnum  { m.resolveStrategy = s; return m }
func (m ModeEnum) WithUDP(s UDPProxyFQDNStrategy) ModeEnum { m.udpProxyFQDNStrategy = s; return m }

var (
	ProxyMode = ModeEnum{mode: ModeProxy, resolveStrategy: ResolveDefault, udpProxyFQDNStrategy: UDPProxyFQDNDefault}
	Direct    = ModeEnum{mode: ModeDirect, resolveStrategy: ResolveDefault, udpProxyFQDNStrategy: UDPProxyFQDNDefault}
	Block     = ModeEnum{mode: ModeBlock, resolveStrategy: ResolveDefault, udpProxyFQDNStrategy: UDPProxyFQDNDefault}
	Bypass    = ModeEnum{mode: ModeBypass, resolveStrategy: ResolveDefault, udpProxyFQDNStrategy: UDPProxyFQDNDefault}
)

type RouteConfig struct {
	DirectResolver       string
	ProxyResolver        string
	ResolveLocally       bool
	UDPProxyFQDNStrategy UDPProxyFQDNStrategy
}

func routeConfigFromContract(in contractroute.Config) *RouteConfig {
	return &RouteConfig{
		DirectResolver:       in.DirectResolver,
		ProxyResolver:        in.ProxyResolver,
		ResolveLocally:       in.ResolveLocally,
		UDPProxyFQDNStrategy: parseUDPProxyFQDNStrategy(in.UdpProxyFqdnStrategy),
	}
}

func modeEnumFromRule(rule contractroute.RouteRule) ModeEnum {
	return ModeEnum{
		Tag:                  rule.Tag,
		resolver:             rule.Resolver,
		mode:                 parseMode(rule.Mode),
		resolveStrategy:      parseResolveStrategy(rule.ResolveStrategy),
		udpProxyFQDNStrategy: parseUDPProxyFQDNStrategy(rule.UdpProxyFqdnStrategy),
	}
}

func parseMode(value string) Mode {
	switch value {
	case "proxy":
		return ModeProxy
	case "direct":
		return ModeDirect
	case "block":
		return ModeBlock
	case "bypass", "":
		return ModeBypass
	default:
		return ModeBypass
	}
}

func parseResolveStrategy(value string) ResolveStrategy {
	switch value {
	case "only_ipv4", "resolve_strategy_only_ipv4":
		return ResolveOnlyIPv4
	case "prefer_ipv4", "resolve_strategy_prefer_ipv4":
		return ResolvePreferIPv4
	case "only_ipv6", "resolve_strategy_only_ipv6":
		return ResolveOnlyIPv6
	case "prefer_ipv6", "resolve_strategy_prefer_ipv6":
		return ResolvePreferIPv6
	default:
		return ResolveDefault
	}
}

func parseUDPProxyFQDNStrategy(value string) UDPProxyFQDNStrategy {
	switch value {
	case "resolve", "udp_proxy_fqdn_strategy_resolve":
		return UDPProxyFQDNResolve
	case "skip_resolve", "udp_proxy_fqdn_strategy_skip_resolve":
		return UDPProxyFQDNSkipResolve
	default:
		return UDPProxyFQDNDefault
	}
}

func uint32Ptr(v uint32) *uint32 { return &v }

func stringPtr(v string) *string { return &v }

func formatUint64(v uint64) string {
	return strconv.FormatUint(v, 10)
}
