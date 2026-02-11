package config

import (
	mrand "math/rand/v2"
	"net/netip"
	"runtime"
)

func FakeipV4UlaGenerate() netip.Prefix {
	ip := [4]byte{10, byte(mrand.IntN(256)), 0, 0}

	return netip.PrefixFrom(netip.AddrFrom4(ip), 16)
}

func FakeipV6UlaGenerate() netip.Prefix {
	ip := [16]byte{
		253,
		byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)),
		255, 255,
	}

	return netip.PrefixFrom(netip.AddrFrom16(ip), 64)
}

func TunV6UlaGenerate() netip.Prefix {
	ip := [16]byte{
		253, //fd
		byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)), byte(mrand.IntN(256)),
		255, 255,
		0, 0, 0, 0, 0, 0, 0, 1,
	}

	return netip.PrefixFrom(netip.AddrFrom16(ip), 64)
}

func TunV4UlaGenerate() netip.Prefix {
	ip := [4]byte{172, byte(mrand.IntN(16) + 16), byte(mrand.IntN(256)), 1}
	return netip.PrefixFrom(netip.AddrFrom4(ip), 24)
}

func DefaultSetting(path string) *Setting {
	tunname := "tun0"
	switch runtime.GOOS {
	case "darwin":
		tunname = "utun0"
	case "windows":
		tunname = "wintun"
	}

	fakev4 := FakeipV4UlaGenerate().String()
	fakev6 := FakeipV6UlaGenerate().String()

	return &Setting{
		Ipv6:                true,
		UseDefaultInterface: true,
		NetInterface:        "",
		SystemProxy: &SystemProxy{
			Http:   true,
			Socks5: false,
		},
		Bypass: &BypassConfig{
			DirectResolver: "bootstrap",
			ProxyResolver:  "bootstrap",
			Lists: map[string]*List{
				"LAN": {
					ListType: ListTypeHost,
					Name:     "LAN",
					Local: &ListLocal{
						Lists: []string{
							"0.0.0.0/8",
							"10.0.0.0/8",
							"100.64.0.0/10",
							"127.0.0.1/8",
							"169.254.0.0/16",
							"172.16.0.0/12",
							"192.0.0.0/29",
							"192.0.2.0/24",
							"192.88.99.0/24",
							"192.168.0.0/16",
							"198.18.0.0/15",
							"198.51.100.0/24",
							"203.0.113.0/24",
							"224.0.0.0/3",
							"fc00::/7",
							"fe80::/10",
							"ff00::/8",
							"localhost",
						},
					},
				},
			},
			RulesV2: []*RuleV2{
				{
					Name:                 "LAN",
					Mode:                 ModeDirect,
					Tag:                  "LAN",
					ResolveStrategy:      ResolveStrategyDefault,
					UdpProxyFqdnStrategy: UdpProxyFqdnStrategyDefault,
					Rules: []*Or{
						{
							Rules: []*Rule{
								{
									Host: &HostRule{
										List: "LAN",
									},
								},
							},
						},
					},
				},
			},
			MaxminddbGeoip: &MaxminddbGeoip{
				DownloadUrl: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-without-asn.mmdb",
				Error:       "NOT DOWNLOAD",
			},
		},
		Dns: &DnsConfig{
			Server:           "127.0.0.1:5353",
			Fakedns:          false,
			FakednsIpRange:   fakev4,
			FakednsIpv6Range: fakev6,
			FakednsWhitelist: []string{
				"*.msftncsi.com",
				"*.msftconnecttest.com",
				"ping.archlinux.org",
				// for macos
				"mask.icloud.com",
				"mask-h2.icloud.com",
				"mask.apple-dns.net",
			},
			Resolver: map[string]*Dns{
				"bootstrap": {
					Host: "8.8.8.8",
					Type: DnsTypeUdp,
				},
			},
			Hosts: map[string]string{"example.com": "example.com"},
		},
		Logcat: &Logcat{
			Level: LogLevelDebug,
			Save:  true,
		},

		Server: &InboundConfig{
			HijackDns:       true,
			HijackDnsFakeip: true,
			Sniff: &Sniff{
				Enabled: true,
			},
			Inbounds: map[string]*Inbound{
				"mixed": {
					Name:    "mixed",
					Enabled: true,
					Tcpudp: &Tcpudp{
						Host:    "127.0.0.1:1080",
						Control: TcpUdpControlAll,
					},
					Mix: &Mixed{},
				},
				"tun": {
					Name:    "tun",
					Enabled: false,
					Empty:   &Empty{},
					Tun: &Tun{
						Name:          "tun://" + tunname,
						Mtu:           9000,
						Portal:        TunV4UlaGenerate().String(),
						PortalV6:      TunV6UlaGenerate().String(),
						SkipMulticast: true,
						Driver:        EndpointDriverSystemGvisor,
						Route: &Route{
							Routes: []string{
								fakev4,
								fakev6,
							},
						},
					},
				},
				"yuubinsya": {
					Name:    "yuubinsya",
					Enabled: false,
					Tcpudp: &Tcpudp{
						Host:    "127.0.0.1:40501",
						Control: DisableUdp,
					},
					Yuubinsya: &InboundYuubinsya{
						Password: "password",
					},
				},
			},
		},
		AdvancedConfig: &AdvancedConfig{},
		ConfigVersion:  &ConfigVersion{},
		Platform:       &Platform{},
	}
}
