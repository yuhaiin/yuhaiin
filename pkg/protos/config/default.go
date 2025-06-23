package config

import (
	"path/filepath"
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"google.golang.org/protobuf/proto"
)

func DefaultSetting(path string) *Setting {
	tunname := "tun0"
	if runtime.GOOS == "darwin" {
		tunname = "utun0"
	} else if runtime.GOOS == "windows" {
		tunname = "wintun"
	}

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
			Lists:          map[string]*bypass.List{},
			RulesV2:        []*bypass.Rulev2{},
			CustomRuleV3: []*bypass.ModeConfig{
				bypass.ModeConfig_builder{
					Mode: bypass.Mode_direct.Enum(),
					Tag:  proto.String("LAN"),
					Hostname: []string{
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
				bypass.ModeConfig_builder{
					Hostname: []string{"dns.google"},
					Mode:     bypass.Mode_proxy.Enum(),
					Tag:      proto.String("remote_dns"),
				}.Build(),
				bypass.ModeConfig_builder{
					Hostname: []string{
						"223.5.5.5",
						"file:" + filepath.Join(filepath.Dir(path), "CN.conf"),
					},
					Mode: bypass.Mode_direct.Enum(),
				}.Build(),
				bypass.ModeConfig_builder{
					Hostname: []string{
						"example.block.domain.com",
					},
					Mode: bypass.Mode_block.Enum(),
				}.Build(),
			},
			RemoteRules: []*bypass.RemoteRule{
				bypass.RemoteRule_builder{
					Enabled: proto.Bool(false),
					Name:    proto.String("default"),
					File: bypass.RemoteRuleFile_builder{
						Path: proto.String(filepath.Join(filepath.Dir(path), "yuhaiin.conf")),
					}.Build(),
				}.Build(),
				bypass.RemoteRule_builder{
					Enabled: proto.Bool(false),
					Name:    proto.String("default_remote"),
					Http: bypass.RemoteRuleHttp_builder{
						Url: proto.String("https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/remote.conf"),
					}.Build(),
				}.Build(),
			},
		}).Build(),
		Dns: pd.DnsConfig_builder{
			Server:           proto.String("127.0.0.1:5353"),
			Fakedns:          proto.Bool(false),
			FakednsIpRange:   proto.String("10.0.2.1/16"),
			FakednsIpv6Range: proto.String("fc00::/64"),
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
						Portal:        proto.String("172.19.0.1/24"),
						PortalV6:      proto.String("fdfe:dcba:9876::1/64"),
						SkipMulticast: proto.Bool(true),
						Driver:        listener.Tun_system_gvisor.Enum(),
						Route: listener.Route_builder{
							Routes: []string{
								"10.0.2.1/16",
								"fc00::/64",
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
