package yuhaiin

import "encoding/json"

var (
	NewHTTPPortKey    = "http_port"
	NewYuhaiinPortKey = "yuhaiin_port"
	NewHostsKey       = "hosts"
)

var (
	defaultBoolValue = map[string]byte{
		AllowLanKey:               0,
		AppendHttpProxyToVpnKey:   0,
		Ipv6ProxyKey:              1,
		NetworkSpeedKey:           0,
		AdvAutoConnectKey:         0,
		AdvPerAppKey:              0,
		AdvAppBypassKey:           0,
		UdpProxyFqdnKey:           0,
		SniffKey:                  1,
		DnsHijacking:              1,
		RemoteDnsResolveDomainKey: 0,
		SaveLogcat:                0,
	}

	disAllowAppList, _ = json.Marshal([]string{
		// RCS/Jibe https://github.com/tailscale/tailscale/issues/2322
		"com.google.android.apps.messaging",
		// Android Auto https://github.com/tailscale/tailscale/issues/3828
		"com.google.android.projection.gearhead",
		// GoPro https://github.com/tailscale/tailscale/issues/2554
		"com.gopro.smarty",
		// Sonos https://github.com/tailscale/tailscale/issues/2548
		"com.sonos.acr",
		"com.sonos.acr2",
		// Google Chromecast https://github.com/tailscale/tailscale/issues/3636
		"com.google.android.apps.chromecast.app",
		// Voicemail https://github.com/tailscale/tailscale/issues/13199
		"com.samsung.attvvm",
		"com.att.mobile.android.vvm",
		"com.tmobile.vvm.application",
		"com.metropcs.service.vvm",
		"com.mizmowireless.vvm",
		"com.vna.service.vvm",
		"com.dish.vvm",
		"com.comcast.modesto.vvm.client",
		// Android Connectivity Service https://github.com/tailscale/tailscale/issues/14128
		"com.google.android.apps.scone",

		// myself
		"io.github.yuhaiin",
	})

	defaultStringValue = map[string]string{
		AdvRouteKey:         AdvRoutes[0],
		AdvFakeDnsCidrKey:   "10.0.2.1/16",
		AdvFakeDnsv6CidrKey: "fc00::/64",
		AdvTunDriverKey:     TunDriversValue[2],
		AdvAppListKey:       string(disAllowAppList),
		LogLevel:            LogLevels[2],

		RuleUpdateBypassFileKey: "https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/remote.conf",
		// RemoteRulesKey:       "[]",
		// rules
		RuleBlock:  "",
		RuleProxy:  "",
		RuleDirect: "",

		BypassTcpKey: AdvBypassModeValue[0],
		BypassUdpKey: AdvBypassModeValue[0],

		DnsHostsKey: `{"example.com": "127.0.0.1"}`,

		RemoteDnsHostKey:          "cloudflare.com",
		RemoteDnsTypeKey:          DnsTypesValue[2],
		RemoteDnsSubnetKey:        "",
		RemoteDnsTlsServerNameKey: "",

		LocalDnsHostKey:          "1.1.1.1",
		LocalDnsTypeKey:          DnsTypesValue[2],
		LocalDnsSubnetKey:        "",
		LocalDnsTlsServerNameKey: "",

		BootstrapDnsHostKey:          "1.1.1.1",
		BootstrapDnsTypeKey:          DnsTypesValue[2],
		BootstrapDnsSubnetKey:        "",
		BootstrapDnsTlsServerNameKey: "",
	}

	defaultIntValue = map[string]int32{
		AdvDnsPortKey:     0,
		NewHTTPPortKey:    0,
		NewYuhaiinPortKey: 3500,
	}

	defaultLangValue  = map[string]int64{}
	defaultFloatValue = map[string]float32{}
)
