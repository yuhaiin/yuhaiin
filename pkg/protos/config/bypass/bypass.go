package bypass

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

func (f *ModeConfig) ToModeEnum() ModeEnum {
	if f.ResolveStrategy == ResolveStrategy_default && f.Tag == "" && f.UdpProxyFqdnStrategy != 0 {
		return f.Mode
	}

	return &modeConfig{
		f.Tag,
		f.Mode,
		f.ResolveStrategy,
		f.UdpProxyFqdnStrategy,
	}
}

type modeConfig struct {
	Tag             string
	mode            Mode
	ResolveStrategy ResolveStrategy
	udpProxyFqdn    UdpProxyFqdnStrategy
}

func (m modeConfig) Mode() Mode                          { return m.mode }
func (m modeConfig) GetTag() string                      { return m.Tag }
func (modeConfig) Unknown() bool                         { return false }
func (m modeConfig) GetResolveStrategy() ResolveStrategy { return m.ResolveStrategy }
func (m modeConfig) UdpProxyFqdn() UdpProxyFqdnStrategy  { return m.udpProxyFqdn }
