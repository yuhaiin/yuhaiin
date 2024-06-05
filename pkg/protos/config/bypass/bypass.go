package bypass

import (
	"bytes"
	"strings"
)

type ModeEnum interface {
	Mode() Mode
	Unknown() bool
	GetTag() string
	GetResolveStrategy() ResolveStrategy
	UdpProxyFqdn() UdpProxyFqdnStrategy
}

func (m Mode) Mode() Mode { return m }
func (m Mode) Unknown() bool {
	_, ok := Mode_name[int32(m)]
	return !ok
}

func (Mode) GetTag() string                      { return "" }
func (Mode) GetResolveStrategy() ResolveStrategy { return ResolveStrategy_default }
func (m Mode) UdpProxyFqdn() UdpProxyFqdnStrategy {
	return UdpProxyFqdnStrategy_udp_proxy_fqdn_strategy_default
}

func (f *ModeConfig) StoreKV(fs [][]byte) {
	for _, x := range fs {
		var k, v []byte
		i := bytes.IndexByte(x, '=')
		if i == -1 {
			k = x
			v = []byte("true")
		} else {
			k = x[:i]
			v = x[i+1:]
		}

		key := strings.ToLower(string(k))
		value := strings.ToLower(string(v))

		switch key {
		case "tag":
			f.Tag = value
		case "resolve_strategy":
			f.ResolveStrategy = ResolveStrategy(ResolveStrategy_value[value])
		case "udp_proxy_fqdn":
			if value == "true" {
				f.UdpProxyFqdnStrategy = UdpProxyFqdnStrategy_skip_resolve
			} else {
				f.UdpProxyFqdnStrategy = UdpProxyFqdnStrategy_resolve
			}
		}
	}
}

func (f *ModeConfig) ToModeEnum() ModeEnum {
	if f.ResolveStrategy == ResolveStrategy_default && f.Tag == "" && f.UdpProxyFqdnStrategy != 0 {
		return f.Mode
	}

	return &modeConfig{
		f.Mode,
		f.Tag,
		f.ResolveStrategy,
		f.UdpProxyFqdnStrategy,
	}
}

type modeConfig struct {
	mode            Mode
	Tag             string
	ResolveStrategy ResolveStrategy
	udpProxyFqdn    UdpProxyFqdnStrategy
}

func (m modeConfig) Mode() Mode                          { return m.mode }
func (m modeConfig) GetTag() string                      { return m.Tag }
func (modeConfig) Unknown() bool                         { return false }
func (m modeConfig) GetResolveStrategy() ResolveStrategy { return m.ResolveStrategy }
func (m modeConfig) UdpProxyFqdn() UdpProxyFqdnStrategy  { return m.udpProxyFqdn }
