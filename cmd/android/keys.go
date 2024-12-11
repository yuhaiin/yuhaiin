package yuhaiin

var (
	AllowLanKey     = "allow_lan"
	AppendHTTPProxy = "Append HTTP Proxy to VPN"
	IPv6Key         = "ipv6"
	NetworkSpeedKey = "network_speed"
	AutoConnectKey  = "auto_connect"
	PerAppKey       = "per_app"
	AppBypassKey    = "app_bypass"
	UDPProxyFQDNKey = "UDP proxy FQDN"
	SniffKey        = "Sniff"
	SaveLogcatKey   = "save_logcat"

	RouteKey         = "route"
	FakeDNSCIDRKey   = "fake_dns_cidr"
	FakeDNSv6CIDRKey = "fake_dnsv6_cidr"
	TunDriverKey     = "Tun Driver"
	AppListKey       = "app_list"
	LogLevelKey      = "Log Level"
	RuleByPassUrlKey = "Rule Update Bypass"
	RemoteRulesKey   = "remote_rules"
	BlockKey         = "Block"
	ProxyKey         = "Proxy"
	DirectKey        = "Direct"
	TCPBypassKey     = "TCP"
	UDPBypassKey     = "UDP"
	HostsKey         = "hosts"

	DNSPortKey     = "dns_port"
	HTTPPortKey    = "http_port"
	YuhaiinPortKey = "yuhaiin_port"

	DNSHijackingKey = "dns_hijacking"

	RemoteDNSHostKey          = "remote_dns_host"
	RemoteDNSTypeKey          = "remote_dns_type"
	RemoteDNSSubnetKey        = "remote_dns_subnet"
	RemoteDNSTLSServerNameKey = "remote_dns_tls_server_name"
	RemoteDNSResolveDomainKey = "remote_dns_resolve_domain"

	LocalDNSHostKey          = "local_dns_host"
	LocalDNSTypeKey          = "local_dns_type"
	LocalDNSSubnetKey        = "local_dns_subnet"
	LocalDNSTLSServerNameKey = "local_dns_tls_server_name"

	BootstrapDNSHostKey          = "bootstrap_dns_host"
	BootstrapDNSTypeKey          = "bootstrap_dns_type"
	BootstrapDNSSubnetKey        = "bootstrap_dns_subnet"
	BootstrapDNSTLSServerNameKey = "bootstrap_dns_tls_server_name"
)

var (
	defaultBoolValue = map[string]byte{
		AllowLanKey:               0,
		AppendHTTPProxy:           0,
		IPv6Key:                   1,
		NetworkSpeedKey:           0,
		AutoConnectKey:            0,
		PerAppKey:                 0,
		AppBypassKey:              0,
		UDPProxyFQDNKey:           0,
		SniffKey:                  1,
		DNSHijackingKey:           1,
		RemoteDNSResolveDomainKey: 0,
		SaveLogcatKey:             0,
	}

	defaultStringValue = map[string]string{
		RouteKey:         "All (Default)",
		FakeDNSCIDRKey:   "10.0.2.1/16",
		FakeDNSv6CIDRKey: "fc00::/64",
		TunDriverKey:     "system_gvisor",
		AppListKey:       `["io.github.yuhaiin"]`,
		LogLevelKey:      "info",

		RuleByPassUrlKey: "https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/remote.conf",
		RemoteRulesKey:   "[]",
		// rules
		BlockKey:  "",
		ProxyKey:  "",
		DirectKey: "",

		TCPBypassKey: "bypass",
		UDPBypassKey: "bypass",

		HostsKey: `{"example.com": "127.0.0.1"}`,

		RemoteDNSHostKey:          "cloudflare.com",
		RemoteDNSTypeKey:          "doh",
		RemoteDNSSubnetKey:        "",
		RemoteDNSTLSServerNameKey: "",

		LocalDNSHostKey:          "1.1.1.1",
		LocalDNSTypeKey:          "doh",
		LocalDNSSubnetKey:        "",
		LocalDNSTLSServerNameKey: "",

		BootstrapDNSHostKey:          "1.1.1.1",
		BootstrapDNSTypeKey:          "doh",
		BootstrapDNSSubnetKey:        "",
		BootstrapDNSTLSServerNameKey: "",
	}

	defaultIntValue = map[string]int32{
		DNSPortKey:     0,
		HTTPPortKey:    0,
		YuhaiinPortKey: 3500,
	}

	defaultLangValue  = map[string]int64{}
	defaultFloatValue = map[string]float32{}
)
