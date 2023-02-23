package config

import (
	"encoding/json"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"google.golang.org/protobuf/encoding/protojson"
)

func defaultConfig(path string) []byte {
	defaultValue := &config.Setting{
		Ipv6:         false,
		NetInterface: "",
		SystemProxy: &config.SystemProxy{
			Http:   true,
			Socks5: false,
			// linux system set socks5 will make firfox websocket can't connect
			// https://askubuntu.com/questions/890274/slack-desktop-client-on-16-04-behind-proxy-server
		},
		Bypass: &bypass.Config{
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
		Dns: &pd.Config{
			ResolveRemoteDomain: false,
			Server:              "127.0.0.1:5353",
			Fakedns:             false,
			FakednsIpRange:      "10.0.2.1/24",
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
			Hosts: map[string]string{"example.com": "example.com"},
		},
		Logcat: &pl.Logcat{
			Level: pl.LogLevel_debug,
			Save:  true,
		},
		Server: &listener.Config{
			Servers: map[string]*listener.Protocol{
				"http": {
					Name:    "http",
					Enabled: true,
					Protocol: &listener.Protocol_Http{
						Http: &listener.Http{
							Host: "127.0.0.1:8188",
						},
					},
				},
				"socks5": {
					Name:    "socks5",
					Enabled: true,
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
							Gateway:       "172.19.0.1",
							Portal:        "172.19.0.2",
							DnsHijacking:  true,
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

	data, _ := protojson.Marshal(defaultValue)
	return data
}

func SetDefault(targetJSON, defaultJSON []byte) []byte {
	m1 := make(map[string]any)
	def := make(map[string]any)

	json.Unmarshal(targetJSON, &m1)
	json.Unmarshal(defaultJSON, &def)

	setDefault(m1, def)

	data, _ := json.Marshal(m1)
	return data
}

func setDefault(m1, md map[string]any) {
	for k, v := range md {
		j1, ok := m1[k]
		if !ok {
			m1[k] = v
			continue
		}

		z1, ok1 := j1.(map[string]any)
		d1, ok2 := v.(map[string]any)

		if ok1 && ok2 {
			setDefault(z1, d1)
		}
	}
}
