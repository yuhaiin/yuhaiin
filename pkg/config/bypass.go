package config

type Mode int32

const (
	ModeBypass Mode = 0
	ModeDirect Mode = 1
	ModeProxy  Mode = 2
	ModeBlock  Mode = 3
)

type ConfigV2 struct {
	UdpProxyFqdn   UdpProxyFqdnStrategy `json:"udp_proxy_fqdn,omitempty"`
	ResolveLocally bool                 `json:"resolve_locally,omitempty"`
	DirectResolver string               `json:"direct_resolver,omitempty"`
	ProxyResolver  string               `json:"proxy_resolver,omitempty"`
}

type MaxminddbGeoip struct {
	DownloadUrl string `json:"download_url,omitempty"`
	Error       string `json:"error,omitempty"`
}

type BypassConfig struct {
	UdpProxyFqdn   UdpProxyFqdnStrategy `json:"udp_proxy_fqdn,omitempty"`
	ResolveLocally bool                 `json:"resolve_locally,omitempty"`
	DirectResolver string               `json:"direct_resolver,omitempty"`
	ProxyResolver  string               `json:"proxy_resolver,omitempty"`

	RulesV2        []*RuleV2           `json:"rules_v2,omitempty"`
	Lists          map[string]*List    `json:"lists,omitempty"`
	MaxminddbGeoip *MaxminddbGeoip     `json:"maxminddb_geoip,omitempty"`
	RefreshConfig  *RefreshConfig      `json:"refresh_config,omitempty"`
}

type RefreshConfig struct {
	RefreshInterval uint64 `json:"refresh_interval,omitempty"`
	LastRefreshTime uint64 `json:"last_refresh_time,omitempty"`
	Error           string `json:"error,omitempty"`
}

type ResolveStrategy int32

const (
	ResolveStrategyDefault    ResolveStrategy = 0
	ResolveStrategyPreferIpv4 ResolveStrategy = 1
	ResolveStrategyOnlyIpv4   ResolveStrategy = 2
	ResolveStrategyPreferIpv6 ResolveStrategy = 3
	ResolveStrategyOnlyIpv6   ResolveStrategy = 4
)

type UdpProxyFqdnStrategy int32

const (
	UdpProxyFqdnStrategyDefault     UdpProxyFqdnStrategy = 0
	UdpProxyFqdnStrategyResolve     UdpProxyFqdnStrategy = 1
	UdpProxyFqdnStrategySkipResolve UdpProxyFqdnStrategy = 2
)

type ModeConfig struct {
	Mode                   Mode                 `json:"mode,omitempty"`
	Tag                    string               `json:"tag,omitempty"`
	Hostname               []string             `json:"hostname,omitempty"`
	ResolveStrategy        ResolveStrategy      `json:"resolve_strategy,omitempty"`
	UdpProxyFqdnStrategy   UdpProxyFqdnStrategy `json:"udp_proxy_fqdn_strategy,omitempty"`
	Resolver               string               `json:"resolver,omitempty"`
	ErrorMsgs              map[string]string    `json:"error_msg,omitempty"`
}

type RemoteRule struct {
	Enabled     bool            `json:"enabled,omitempty"`
	Name        string          `json:"name,omitempty"`
	File        *RemoteRuleFile `json:"file,omitempty"`
	Http        *RemoteRuleHttp `json:"http,omitempty"`
	ErrorMsg    string          `json:"error_msg,omitempty"`
	DefaultMode *ModeConfig     `json:"default_mode,omitempty"`
}

type RemoteRuleFile struct {
	Path string `json:"path,omitempty"`
}

type RemoteRuleHttp struct {
	Url    string `json:"url,omitempty"`
	Method string `json:"method,omitempty"`
}

type HostRule struct {
	List string `json:"list,omitempty"`
}

type ProcessRule struct {
	List string `json:"list,omitempty"`
}

type Source struct {
	Name  string   `json:"name,omitempty"`
	Names []string `json:"names,omitempty"`
}

type Port struct {
	Ports string `json:"ports,omitempty"`
}

type Geoip struct {
	Countries string `json:"countries,omitempty"`
}

type Rule struct {
	Host    *HostRule    `json:"host,omitempty"`
	Process *ProcessRule `json:"process,omitempty"`
	Inbound *Source      `json:"inbound,omitempty"`
	Network *Network     `json:"network,omitempty"`
	Port    *Port        `json:"port,omitempty"`
	Geoip   *Geoip       `json:"geoip,omitempty"`
}

type NetworkType int32

const (
	NetworkTypeUnknown NetworkType = 0
	NetworkTypeTcp     NetworkType = 1
	NetworkTypeUdp     NetworkType = 2
)

type Network struct {
	Network NetworkType `json:"network,omitempty"`
}

type Or struct {
	Rules []*Rule `json:"rules,omitempty"`
}

type RuleV2 struct {
	Name                 string               `json:"name,omitempty"`
	Mode                 Mode                 `json:"mode,omitempty"`
	Tag                  string               `json:"tag,omitempty"`
	ResolveStrategy      ResolveStrategy      `json:"resolve_strategy,omitempty"`
	UdpProxyFqdnStrategy UdpProxyFqdnStrategy `json:"udp_proxy_fqdn_strategy,omitempty"`
	Resolver             string               `json:"resolver,omitempty"`
	Rules                []*Or                `json:"rules,omitempty"`
}

type ListType int32

const (
	ListTypeHost        ListType = 0
	ListTypeProcess     ListType = 1
	ListTypeHostsAsHost ListType = 2
)

type List struct {
	ListType  ListType    `json:"type,omitempty"`
	Name      string      `json:"name,omitempty"`
	Local     *ListLocal  `json:"local,omitempty"`
	Remote    *ListRemote `json:"remote,omitempty"`
	ErrorMsgs []string    `json:"error_msgs,omitempty"`
}

type ListLocal struct {
	Lists []string `json:"lists,omitempty"`
}

type ListRemote struct {
	Urls []string `json:"urls,omitempty"`
}
