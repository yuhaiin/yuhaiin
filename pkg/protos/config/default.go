package config

import (
	mrand "math/rand/v2"
	"net/netip"
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"google.golang.org/protobuf/proto"
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

	return (&Setting_builder{
		Ipv6:                proto.Bool(true),
		UseDefaultInterface: proto.Bool(true),
		NetInterface:        proto.String(""),
		SystemProxy: SystemProxy_builder{
			Http:   proto.Bool(true),
			Socks5: proto.Bool(false),
			// linux system set socks5 will make firfox websocket can't connect
			// https://askubuntu.com/questions/890274/slack-desktop-client-on-16-04-behind-proxy-server
		}.Build(),
		Bypass: (&bypass.Config_builder{
			Tcp:            bypass.Mode_bypass.Enum(),
			Udp:            bypass.Mode_bypass.Enum(),
			DirectResolver: proto.String("bootstrap"),
			ProxyResolver:  proto.String("bootstrap"),
			EnabledV2:      proto.Bool(true),
			Lists: map[string]*bypass.List{
				"LAN": bypass.List_builder{
					ListType: bypass.List_host.Enum(),
					Name:     proto.String("LAN"),
					Local: bypass.ListLocal_builder{
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
					}.Build(),
				}.Build(),
			},
			RulesV2: []*bypass.Rulev2{
				bypass.Rulev2_builder{
					Name:                 proto.String("LAN"),
					Mode:                 bypass.Mode_direct.Enum(),
					Tag:                  proto.String("LAN"),
					ResolveStrategy:      bypass.ResolveStrategy_default.Enum(),
					UdpProxyFqdnStrategy: bypass.UdpProxyFqdnStrategy_udp_proxy_fqdn_strategy_default.Enum(),
					Rules: []*bypass.Or{
						bypass.Or_builder{
							Rules: []*bypass.Rule{
								bypass.Rule_builder{
									Host: bypass.Host_builder{
										List: proto.String("LAN"),
									}.Build(),
								}.Build(),
							},
						}.Build(),
					},
				}.Build(),
			},
			CustomRuleV3: []*bypass.ModeConfig{},
			RemoteRules:  []*bypass.RemoteRule{},
		}).Build(),
		Dns: pd.DnsConfig_builder{
			Server:           proto.String("127.0.0.1:5353"),
			Fakedns:          proto.Bool(false),
			FakednsIpRange:   proto.String(fakev4),
			FakednsIpv6Range: proto.String(fakev6),
			FakednsWhitelist: []string{
				"*.msftncsi.com",
				"*.msftconnecttest.com",
				"ping.archlinux.org",
				// for macos, see:
				//  https://github.com/immortalwrt/homeproxy/discussions/155
				//  https://github.com/vernesong/OpenClash/issues/4370
				"mask.icloud.com",
				"mask-h2.icloud.com",
				"mask.apple-dns.net",
			},
			Resolver: map[string]*pd.Dns{
				"bootstrap": pd.Dns_builder{
					Host: proto.String("8.8.8.8"),
					Type: pd.Type_udp.Enum(),
				}.Build(),
			},
			Hosts: map[string]string{"example.com": "example.com"},
		}.Build(),
		Logcat: pl.Logcat_builder{
			Level: pl.LogLevel_debug.Enum(),
			Save:  proto.Bool(true),
		}.Build(),

		Server: listener.InboundConfig_builder{
			HijackDns:       proto.Bool(true),
			HijackDnsFakeip: proto.Bool(true),
			Sniff: listener.Sniff_builder{
				Enabled: proto.Bool(true),
			}.Build(),
			Inbounds: map[string]*listener.Inbound{
				"mixed": listener.Inbound_builder{
					Name:    proto.String("mixed"),
					Enabled: proto.Bool(true),
					Tcpudp: listener.Tcpudp_builder{
						Host:    proto.String("127.0.0.1:1080"),
						Control: listener.TcpUdpControl_tcp_udp_control_all.Enum(),
					}.Build(),
					Mix: &listener.Mixed{},
				}.Build(),
				"tun": listener.Inbound_builder{
					Name:    proto.String("tun"),
					Enabled: proto.Bool(false),
					Empty:   &listener.Empty{},
					Tun: listener.Tun_builder{
						Name:          proto.String("tun://" + tunname),
						Mtu:           proto.Int32(9000),
						Portal:        proto.String(TunV4UlaGenerate().String()),
						PortalV6:      proto.String(TunV6UlaGenerate().String()),
						SkipMulticast: proto.Bool(true),
						Driver:        listener.Tun_system_gvisor.Enum(),
						Route: listener.Route_builder{
							Routes: []string{
								fakev4,
								fakev6,
							},
						}.Build(),
					}.Build(),
				}.Build(),
				"yuubinsya": listener.Inbound_builder{
					Name:    proto.String("yuubinsya"),
					Enabled: proto.Bool(false),
					Tcpudp: listener.Tcpudp_builder{
						Host:    proto.String("127.0.0.1:40501"),
						Control: listener.TcpUdpControl_disable_udp.Enum(),
					}.Build(),
					Yuubinsya: listener.Yuubinsya_builder{
						Password: proto.String("password"),
					}.Build(),
				}.Build(),
			},
		}.Build(),
		AdvancedConfig: &AdvancedConfig{},
		ConfigVersion:  &ConfigVersion{},
		Platform:       &Platform{},
	}).Build()
}
