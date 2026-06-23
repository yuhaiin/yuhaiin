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
	Host          string  `json:"host"`
	Type          DnsType `json:"type"`
	Subnet        string  `json:"subnet"`
	TlsServername string  `json:"tls_servername"`
}

type DnsConfig struct {
	Server              string         `json:"server"`
	Fakedns             bool           `json:"fakedns"`
	FakednsIpRange      string         `json:"fakedns_ip_range"`
	FakednsIpv6Range    string         `json:"fakedns_ipv6_range"`
	FakednsWhitelist    []string       `json:"fakedns_whitelist"`
	FakednsSkipCheckList []string       `json:"fakedns_skip_check_list"`
	Hosts               map[string]string `json:"hosts"`
	Resolver            map[string]Dns `json:"resolver"`
}

type FakeDnsConfig struct {
	Enabled       bool     `json:"enabled"`
	Ipv4Range     string   `json:"ipv4_range"`
	Ipv6Range     string   `json:"ipv6_range"`
	Whitelist     []string `json:"whitelist"`
	SkipCheckList []string `json:"skip_check_list"`
}

type Server struct {
	Host string `json:"host"`
}

type DnsConfigV2 struct {
	Server   *Server           `json:"server"`
	Fakedns  *FakeDnsConfig    `json:"fakedns"`
	Hosts    map[string]string `json:"hosts"`
	Resolver map[string]Dns     `json:"resolver"`
}
