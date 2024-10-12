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
		Bypass: &bypass.Config{
			Tcp: bypass.Mode_bypass,
			Udp: bypass.Mode_bypass,
			CustomRuleV3: []*bypass.ModeConfig{
				{
					Mode: bypass.Mode_direct,
					Tag:  "LAN",
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
				},
				{
					Hostname: []string{"dns.google"},
					Mode:     bypass.Mode_proxy,
					Tag:      "remote_dns",
				},
				{
					Hostname: []string{
						"223.5.5.5",
						"file:" + filepath.Join(filepath.Dir(path), "CN.conf"),
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
			RemoteRules: []*bypass.RemoteRule{
				{
					Enabled: false,
					Name:    "default",
					Object: &bypass.RemoteRule_File{
						File: &bypass.RemoteRuleFile{
							Path: filepath.Join(filepath.Dir(path), "yuhaiin.conf"),
						},
					},
				},
				{
					Enabled: false,
					Name:    "default_remote",
					Object: &bypass.RemoteRule_Http{
						Http: &bypass.RemoteRuleHttp{
							Url: "https://raw.githubusercontent.com/yuhaiin/kitte/main/yuhaiin/remote.conf",
						},
					},
				},
			},
		},
		Dns: &pd.DnsConfig{
			Server:           "127.0.0.1:5353",
			Fakedns:          false,
			FakednsIpRange:   "10.0.2.1/16",
			FakednsIpv6Range: "fc00::/64",
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
			Sniff: &listener.Sniff{
				Enabled: true,
			},
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
		},
		Platform: &config.Platform{},
	}
}
