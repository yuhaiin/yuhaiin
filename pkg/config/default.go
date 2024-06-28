package config

import (
	"path/filepath"
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
)

func defaultSetting(path string) *config.Setting {
	tunname := "tun0"
	if runtime.GOOS == "darwin" {
		tunname = "utun0"
	} else if runtime.GOOS == "windows" {
		tunname = "wintun"
	}

	return &config.Setting{
		Ipv6:         false,
		NetInterface: "",
		SystemProxy: &config.SystemProxy{
			Http:   true,
			Socks5: false,
			// linux system set socks5 will make firfox websocket can't connect
			// https://askubuntu.com/questions/890274/slack-desktop-client-on-16-04-behind-proxy-server
		},
		Bypass: &bypass.BypassConfig{
			Tcp:        bypass.Mode_bypass,
			Udp:        bypass.Mode_bypass,
			BypassFile: filepath.Join(filepath.Dir(path), "yuhaiin.conf"),
			CustomRuleV3: []*bypass.ModeConfig{
				{
					Hostname: []string{"dns.google"},
					Mode:     bypass.Mode_proxy,
					Tag:      "remote_dns",
				},
				{
					Hostname: []string{
						"223.5.5.5",
					},
					Mode: bypass.Mode_direct,
				},
				{
					Hostname: []string{
						"example.block.domain.com",
					},
					Mode: bypass.Mode_block,
				},
			},
		},
		Dns: &pd.DnsConfig{
			ResolveRemoteDomain: false,
			Server:              "127.0.0.1:5353",
			Fakedns:             false,
			FakednsIpRange:      "10.0.2.1/16",
			FakednsIpv6Range:    "fc00::/64",
			FakednsWhitelist: []string{
				"*.msftncsi.com",
				"*.msftconnecttest.com",
				"ping.archlinux.org",
			},
			Local: &pd.Dns{
				Host: "223.5.5.5",
				Type: pd.Type_doh,
			},
			Remote: &pd.Dns{
				Host: "dns.google",
				Type: pd.Type_doh,
			},
			Bootstrap: &pd.Dns{
				Host: "223.5.5.5",
				Type: pd.Type_udp,
			},
			Resolver: map[string]*pd.Dns{
				"local": {
					Host: "223.5.5.5",
					Type: pd.Type_doh,
				},
				"remote": {
					Host: "dns.google",
					Type: pd.Type_doh,
				},
				"bootstrap": {
					Host: "223.5.5.5",
					Type: pd.Type_udp,
				},
			},
			Hosts: map[string]string{"example.com": "example.com"},
		},
		Logcat: &pl.Logcat{
			Level: pl.LogLevel_debug,
			Save:  true,
		},

		Server: &listener.InboundConfig{
			HijackDns:       true,
			HijackDnsFakeip: true,
			Inbounds: map[string]*listener.Inbound{
				"mixed": {
					Name:    "mixed",
					Enabled: true,
					Network: &listener.Inbound_Tcpudp{
						Tcpudp: &listener.Tcpudp{
							Host:    "127.0.0.1:1080",
							Control: listener.TcpUdpControl_tcp_udp_control_all,
						},
					},
					Protocol: &listener.Inbound_Mix{
						Mix: &listener.Mixed{},
					},
				},
				"tun": {
					Name:    "tun",
					Enabled: false,
					Network: &listener.Inbound_Empty{Empty: &listener.Empty{}},
					Protocol: &listener.Inbound_Tun{
						Tun: &listener.Tun{
							Name:          "tun://" + tunname,
							Mtu:           9000,
							Portal:        "172.19.0.1/24",
							PortalV6:      "fdfe:dcba:9876::1/64",
							SkipMulticast: true,
							Driver:        listener.Tun_system_gvisor,
							Route: &listener.Route{
								Routes: []string{
									"10.0.2.1/16",
									"fc00::/64",
								},
							},
						},
					},
				},
				"yuubinsya": {
					Name:    "yuubinsya",
					Enabled: false,
					Network: &listener.Inbound_Tcpudp{
						Tcpudp: &listener.Tcpudp{
							Host:    "127.0.0.1:40501",
							Control: listener.TcpUdpControl_disable_udp,
						},
					},
					Protocol: &listener.Inbound_Yuubinsya{
						Yuubinsya: &listener.Yuubinsya{
							Password: "password",
						},
					},
				},
			},
			Servers: map[string]*listener.Protocol{},
		},
	}
}
