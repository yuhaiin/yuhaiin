package config

import (
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
)

func defaultSetting(path string) *config.Setting {
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
			FakednsIpRange:      "10.0.2.1/24",
			FakednsWhitelist: []string{
				"*.msftncsi.com",
				"*.msftconnecttest.com",
			},
			Local: &pd.Dns{
				Host: "223.5.5.5",
				Type: pd.Type_doh,
			},
			Remote: &pd.Dns{
				Host:   "dns.google",
				Type:   pd.Type_doh,
				Subnet: "223.5.5.5",
			},
			Bootstrap: &pd.Dns{
				Host: "223.5.5.5",
				Type: pd.Type_udp,
			},
			LocalV2:  "local",
			RemoteV2: "remote",
			Resolver: map[string]*pd.Dns{
				"local": {
					Host: "223.5.5.5",
					Type: pd.Type_doh,
				},
				"remote": {
					Host:   "dns.google",
					Type:   pd.Type_doh,
					Subnet: "223.5.5.5",
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
			Servers: map[string]*listener.Protocol{
				"mixed": {
					Name:    "mixed",
					Enabled: true,
					Protocol: &listener.Protocol_Mix{
						Mix: &listener.Mixed{
							Host: "127.0.0.1:1080",
						},
					},
				},
				"http": {
					Name:    "http",
					Enabled: false,
					Protocol: &listener.Protocol_Http{
						Http: &listener.Http{
							Host: "127.0.0.1:8188",
						},
					},
				},
				"socks5": {
					Name:    "socks5",
					Enabled: false,
					Protocol: &listener.Protocol_Socks5{
						Socks5: &listener.Socks5{
							Host: "127.0.0.1:1080",
						},
					},
				},
				"redir": {
					Name:    "redir",
					Enabled: false,
					Protocol: &listener.Protocol_Redir{
						Redir: &listener.Redir{
							Host: "127.0.0.1:8088",
						},
					},
				},
				"tun": {
					Name:    "tun",
					Enabled: false,
					Protocol: &listener.Protocol_Tun{
						Tun: &listener.Tun{
							Name:          "tun://tun0",
							Mtu:           9000,
							Portal:        "172.19.0.1/24",
							SkipMulticast: true,
						},
					},
				},
				"yuubinsya": {
					Name:    "yuubinsya",
					Enabled: false,
					Protocol: &listener.Protocol_Yuubinsya{
						Yuubinsya: &listener.Yuubinsya{
							Host:     "127.0.0.1:40501",
							Password: "123",
							Protocol: &listener.Yuubinsya_Normal{Normal: &listener.Normal{}},
						},
					},
				},
			},
		},
	}
}
