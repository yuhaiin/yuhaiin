package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	netdns "github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	grpcconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Setting interface {
	grpcconfig.ConfigDaoServer
	AddObserver(Observer)
}

type Observer interface {
	Update(*config.Setting)
}

type ObserverFunc func(*config.Setting)

func (o ObserverFunc) Update(s *config.Setting) { o(s) }

type settingImpl struct {
	grpcconfig.UnimplementedConfigDaoServer
	current *config.Setting
	path    string

	os []Observer

	lock sync.RWMutex
}

func NewConfig(path string) Setting {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Errorln("read config file failed: %v\n", err)
	}

	data = SetDefault(data, defaultConfig(path))

	var pa config.Setting
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, &pa)
	if err != nil {
		log.Errorln("unmarshal config file failed: %v\n", err)
	}

	return &settingImpl{current: &pa, path: path}
}

func (c *settingImpl) Load(context.Context, *emptypb.Empty) (*config.Setting, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.current, nil
}

func (c *settingImpl) Save(_ context.Context, s *config.Setting) (*emptypb.Empty, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	err := save(s, c.path)
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("save settings failed: %w", err)
	}

	c.current = proto.Clone(s).(*config.Setting)

	wg := sync.WaitGroup{}
	for i := range c.os {
		wg.Add(1)
		go func(o Observer) {
			defer wg.Done()
			o.Update(proto.Clone(c.current).(*config.Setting))
		}(c.os[i])
	}
	wg.Wait()

	return &emptypb.Empty{}, nil
}

func (c *settingImpl) AddObserver(o Observer) {
	if o == nil {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	c.os = append(c.os, o)
	o.Update(c.current)
}

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
			CustomRuleV2: map[string]*bypass.ModeConfig{
				"dns.google":               {Mode: bypass.Mode_proxy},
				"223.5.5.5":                {Mode: bypass.Mode_direct},
				"exmaple.block.domain.com": {Mode: bypass.Mode_block},
			},
		},
		Dns: &dns.Config{
			ResolveRemoteDomain: false,
			Server:              "127.0.0.1:5353",
			Fakedns:             false,
			FakednsIpRange:      "10.0.2.1/24",
			Local: &dns.Dns{
				Host: "223.5.5.5",
				Type: dns.Type_doh,
			},
			Remote: &dns.Dns{
				Host:   "dns.google",
				Type:   dns.Type_doh,
				Subnet: "223.5.5.5",
			},
			Bootstrap: &dns.Dns{
				Host: "223.5.5.5",
				Type: dns.Type_udp,
			},
			Hosts: map[string]string{"example.com": "example.com"},
		},
		Logcat: &protolog.Logcat{
			Level: protolog.LogLevel_debug,
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
							Mtu:           1500,
							Gateway:       "172.19.0.1",
							DnsHijacking:  true,
							SkipMulticast: true,
						},
					},
				},
			},
		},
	}

	data, _ := protojson.Marshal(defaultValue)
	return data
}

func save(pa *config.Setting, dir string) error {
	_, err := os.Stat(dir)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(dir), os.ModePerm)
		if err != nil {
			return fmt.Errorf("make dir failed: %w", err)
		}
	}

	if err = check(pa); err != nil {
		return err
	}

	data, err := protojson.MarshalOptions{Multiline: true, Indent: "\t"}.Marshal(pa)
	if err != nil {
		return fmt.Errorf("marshal setting failed: %w", err)
	}

	return os.WriteFile(dir, data, os.ModePerm)
}

func check(pa *config.Setting) error {
	err := checkBypass(pa.Bypass)
	if err != nil {
		return err
	}

	err = CheckBootstrapDns(pa.Dns.Bootstrap)
	if err != nil {
		return err
	}

	return nil
}

func checkBypass(pa *bypass.Config) error {
	if pa.Tcp != bypass.Mode_bypass && pa.Udp != bypass.Mode_bypass {
		return nil
	}
	_, err := os.Stat(pa.BypassFile)
	if err != nil {
		return fmt.Errorf("check bypass file stat failed: %w", err)
	}

	return nil
}

func CheckBootstrapDns(pa *dns.Dns) error {
	addr, err := netdns.ParseAddr(pa.Host, "443")
	if err != nil {
		return err
	}

	if addr.Type() != proxy.IP {
		return fmt.Errorf("dns bootstrap host is only support ip address")
	}

	return nil
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
