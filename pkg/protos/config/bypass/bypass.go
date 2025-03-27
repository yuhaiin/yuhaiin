package bypass

import "unique"

func (m Mode) ToModeEnum() ModeEnum {
	switch m {
	case Mode_proxy:
		return Proxy
	case Mode_direct:
		return Direct
	case Mode_block:
		return Block
	case Mode_bypass:
		return Bypass
	default:
		return Bypass
	}
}

func (m Mode) Unknown() bool {
	_, ok := Mode_name[int32(m)]
	return !ok
}

func (m Mode) Unspecified() bool { return m == Mode_bypass }

func (f *ModeConfig) ToModeEnum() unique.Handle[ModeEnum] {
	return unique.Make(ModeEnum{
		f.GetTag(),
		f.GetResolver(),
		f.GetMode(),
		f.GetResolveStrategy(),
		f.GetUdpProxyFqdnStrategy(),
	})
}

type ModeEnum struct {
	Tag             string
	resolver        string
	mode            Mode
	ResolveStrategy ResolveStrategy
	udpProxyFqdn    UdpProxyFqdnStrategy
}

func (m ModeEnum) Mode() Mode                          { return m.mode }
func (m ModeEnum) GetTag() string                      { return m.Tag }
func (ModeEnum) Unknown() bool                         { return false }
func (m ModeEnum) GetResolveStrategy() ResolveStrategy { return m.ResolveStrategy }
func (m ModeEnum) UdpProxyFqdn() UdpProxyFqdnStrategy  { return m.udpProxyFqdn }
func (m ModeEnum) Resolver() string                    { return m.resolver }

var (
	Proxy = ModeEnum{
		mode:            Mode_proxy,
		ResolveStrategy: ResolveStrategy_default,
		udpProxyFqdn:    UdpProxyFqdnStrategy_udp_proxy_fqdn_strategy_default,
	}
	Direct = ModeEnum{
		mode:            Mode_direct,
		ResolveStrategy: ResolveStrategy_default,
		udpProxyFqdn:    UdpProxyFqdnStrategy_udp_proxy_fqdn_strategy_default,
	}
	Block = ModeEnum{
		mode:            Mode_block,
		ResolveStrategy: ResolveStrategy_default,
		udpProxyFqdn:    UdpProxyFqdnStrategy_udp_proxy_fqdn_strategy_default,
	}
	Bypass = ModeEnum{
		mode:            Mode_bypass,
		ResolveStrategy: ResolveStrategy_default,
		udpProxyFqdn:    UdpProxyFqdnStrategy_udp_proxy_fqdn_strategy_default,
	}
)
