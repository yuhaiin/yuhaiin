package config

type DnsType int32

const (
	DnsTypeReserve DnsType = 0
	DnsTypeUdp     DnsType = 1
	DnsTypeTcp     DnsType = 2
	DnsTypeDoh     DnsType = 3
	DnsTypeDot     DnsType = 4
	DnsTypeDoq     DnsType = 5
	DnsTypeDoh3    DnsType = 6
)

type Dns struct {
	Host          string  `json:"host,omitempty"`
	Type          DnsType `json:"type,omitempty"`
	Subnet        string  `json:"subnet,omitempty"`
	TlsServername string  `json:"tls_servername,omitempty"`
}

type DnsConfig struct {
	Server             string            `json:"server,omitempty"`
	Fakedns            bool              `json:"fakedns,omitempty"`
	FakednsIpRange     string            `json:"fakedns_ip_range,omitempty"`
	FakednsIpv6Range   string            `json:"fakedns_ipv6_range,omitempty"`
	FakednsWhitelist   []string          `json:"fakedns_whitelist,omitempty"`
	FakednsSkipCheckList []string        `json:"fakedns_skip_check_list,omitempty"`
	Hosts              map[string]string `json:"hosts,omitempty"`
	Resolver           map[string]*Dns   `json:"resolver,omitempty"`
}

type FakednsConfig struct {
	Enabled       bool     `json:"enabled,omitempty"`
	Ipv4Range     string   `json:"ipv4_range,omitempty"`
	Ipv6Range     string   `json:"ipv6_range,omitempty"`
	Whitelist     []string `json:"whitelist,omitempty"`
	SkipCheckList []string `json:"skip_check_list,omitempty"`
}

type Server struct {
	Host string `json:"host,omitempty"`
}

type DnsConfigV2 struct {
	Server   *Server           `json:"server,omitempty"`
	Fakedns  *FakednsConfig    `json:"fakedns,omitempty"`
	Hosts    map[string]string `json:"hosts,omitempty"`
	Resolver map[string]*Dns   `json:"resolver,omitempty"`
}
