package config

type Mode int32

const (
	ModeBypass Mode = 0
	ModeDirect Mode = 1
	ModeProxy  Mode = 2
	ModeBlock  Mode = 3
)

type Configv2 struct {
	UdpProxyFqdn   UdpProxyFqdnStrategy `json:"udp_proxy_fqdn"`
	ResolveLocally bool                 `json:"resolve_locally"`
	DirectResolver string               `json:"direct_resolver"`
	ProxyResolver  string               `json:"proxy_resolver"`
}

type BypassConfig struct {
	UdpProxyFqdn   UdpProxyFqdnStrategy `json:"udp_proxy_fqdn"`
	ResolveLocally bool                 `json:"resolve_locally"`
	DirectResolver string               `json:"direct_resolver"`
	ProxyResolver  string               `json:"proxy_resolver"`
	RulesV2        []Rulev2             `json:"rules_v2"`
	Lists          map[string]List      `json:"lists"`
	MaxminddbGeoip *MaxminddbGeoip      `json:"maxminddb_geoip"`
	RefreshConfig  *RefreshConfig       `json:"refresh_config"`
}

type MaxminddbGeoip struct {
	DownloadUrl string `json:"download_url"`
	Error       string `json:"error"`
}

type RefreshConfig struct {
	RefreshInterval uint64 `json:"refresh_interval"`
	LastRefreshTime uint64 `json:"last_refresh_time"`
	Error           string `json:"error"`
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
	Mode                 Mode                 `json:"mode"`
	Tag                  string               `json:"tag"`
	Hostname             []string             `json:"hostname"`
	ResolveStrategy      ResolveStrategy      `json:"resolve_strategy"`
	UdpProxyFqdnStrategy UdpProxyFqdnStrategy `json:"udp_proxy_fqdn_strategy"`
	Resolver             string               `json:"resolver"`
	ErrorMsgs            map[string]string    `json:"error_msg"`
}

type RemoteRule struct {
	Enabled     bool             `json:"enabled"`
	Name        string           `json:"name"`
	Object      RemoteRuleObject `json:"object"`
	ErrorMsg    string           `json:"error_msg"`
	DefaultMode *ModeConfig      `json:"default_mode"`
}

type RemoteRuleObjectType int32

const (
	RemoteRuleObjectTypeFile RemoteRuleObjectType = 0
	RemoteRuleObjectTypeHttp RemoteRuleObjectType = 1
)

type RemoteRuleObject struct {
	Type RemoteRuleObjectType `json:"type"`
	File *RemoteRuleFile      `json:"file,omitempty"`
	Http *RemoteRuleHttp      `json:"http,omitempty"`
}

type RemoteRuleFile struct {
	Path string `json:"path"`
}

type RemoteRuleHttp struct {
	Url    string `json:"url"`
	Method string `json:"method"`
}

type Host struct {
	List string `json:"list"`
}

type Process struct {
	List string `json:"list"`
}

type Source struct {
	Name  string   `json:"name"`
	Names []string `json:"names"`
}

type Port struct {
	Ports string `json:"ports"`
}

type Geoip struct {
	Countries string `json:"countries"`
}

type Rule struct {
	Object RuleObject `json:"object"`
}

type RuleObjectType int32

const (
	RuleObjectTypeHost    RuleObjectType = 0
	RuleObjectTypeProcess RuleObjectType = 1
	RuleObjectTypeInbound RuleObjectType = 2
	RuleObjectTypeNetwork RuleObjectType = 3
	RuleObjectTypePort    RuleObjectType = 4
	RuleObjectTypeGeoip   RuleObjectType = 5
)

type RuleObject struct {
	Type    RuleObjectType `json:"type"`
	Host    *Host          `json:"host,omitempty"`
	Process *Process       `json:"process,omitempty"`
	Inbound *Source        `json:"inbound,omitempty"`
	Network *Network       `json:"network,omitempty"`
	Port    *Port          `json:"port,omitempty"`
	Geoip   *Geoip         `json:"geoip,omitempty"`
}

type Network struct {
	Network NetworkType `json:"network"`
}

type NetworkType int32

const (
	NetworkTypeUnknown NetworkType = 0
	NetworkTypeTcp     NetworkType = 1
	NetworkTypeUdp     NetworkType = 2
)

type Or struct {
	Rules []Rule `json:"rules"`
}

type Rulev2 struct {
	Name                 string               `json:"name"`
	Mode                 Mode                 `json:"mode"`
	Tag                  string               `json:"tag"`
	ResolveStrategy      ResolveStrategy      `json:"resolve_strategy"`
	UdpProxyFqdnStrategy UdpProxyFqdnStrategy `json:"udp_proxy_fqdn_strategy"`
	Resolver             string               `json:"resolver"`
	Rules                []Or                 `json:"rules"`
}

type List struct {
	ListType  ListTypeEnum `json:"type"`
	Name      string       `json:"name"`
	List      ListChoice   `json:"list"`
	ErrorMsgs []string     `json:"error_msgs"`
}

type ListChoiceType int32

const (
	ListChoiceTypeLocal  ListChoiceType = 0
	ListChoiceTypeRemote ListChoiceType = 1
)

type ListChoice struct {
	Type   ListChoiceType `json:"type"`
	Local  *ListLocal     `json:"local,omitempty"`
	Remote *ListRemote    `json:"remote,omitempty"`
}

type ListTypeEnum int32

const (
	ListTypeEnumHost        ListTypeEnum = 0
	ListTypeEnumProcess     ListTypeEnum = 1
	ListTypeEnumHostsAsHost ListTypeEnum = 2
)

type ListLocal struct {
	Lists []string `json:"lists"`
}

type ListRemote struct {
	Urls []string `json:"urls"`
}
