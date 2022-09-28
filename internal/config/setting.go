package config

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	grpcconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
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

type observer struct{ u func(s *config.Setting) }

func (w *observer) Update(s *config.Setting)       { w.u(s) }
func NewObserver(u func(*config.Setting)) Observer { return &observer{u} }

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
		return &emptypb.Empty{}, fmt.Errorf("save settings failed: %v", err)
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
		Bypass: &config.Bypass{
			Tcp:        config.Bypass_bypass,
			Udp:        config.Bypass_bypass,
			BypassFile: filepath.Join(filepath.Dir(path), "yuhaiin.conf"),
			CustomRule: map[string]config.BypassMode{
				"dns.google":               config.Bypass_proxy,
				"223.5.5.5":                config.Bypass_direct,
				"exmaple.block.domain.com": config.Bypass_block,
			},
		},
		Dns: &config.DnsSetting{
			Server:         "127.0.0.1:5353",
			Fakedns:        false,
			FakednsIpRange: "10.0.2.1/24",
			Local: &config.Dns{
				Host: "223.5.5.5",
				Type: config.Dns_doh,
			},
			Remote: &config.Dns{
				Host:   "dns.google",
				Type:   config.Dns_doh,
				Subnet: "223.5.5.5",
			},
			Bootstrap: &config.Dns{
				Host: "223.5.5.5",
				Type: config.Dns_udp,
			},
		},
		Logcat: &protolog.Logcat{
			Level: protolog.LogLevel_debug,
			Save:  true,
		},
		Server: &config.Server{
			Servers: map[string]*config.ServerProtocol{
				"http": {
					Name:    "http",
					Enabled: true,
					Protocol: &config.ServerProtocol_Http{
						Http: &config.Http{
							Host: "127.0.0.1:8188",
						},
					},
				},
				"socks5": {
					Name:    "socks5",
					Enabled: true,
					Protocol: &config.ServerProtocol_Socks5{
						Socks5: &config.Socks5{
							Host: "127.0.0.1:1080",
						},
					},
				},
				"redir": {
					Name:    "redir",
					Enabled: false,
					Protocol: &config.ServerProtocol_Redir{
						Redir: &config.Redir{
							Host: "127.0.0.1:8088",
						},
					},
				},
				"tun": {
					Name:    "tun",
					Enabled: false,
					Protocol: &config.ServerProtocol_Tun{
						Tun: &config.Tun{
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
			return fmt.Errorf("make dir failed: %v", err)
		}
	}

	if err = check(pa); err != nil {
		return err
	}

	data, err := protojson.MarshalOptions{Multiline: true, Indent: "\t"}.Marshal(pa)
	if err != nil {
		return fmt.Errorf("marshal setting failed: %v", err)
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

func checkBypass(pa *config.Bypass) error {
	if pa.Tcp != config.Bypass_bypass && pa.Udp != config.Bypass_bypass {
		return nil
	}
	_, err := os.Stat(pa.BypassFile)
	if err != nil {
		return fmt.Errorf("check bypass file stat failed: %w", err)
	}

	return nil
}

func CheckBootstrapDns(pa *config.Dns) error {
	hostname, err := GetDNSHostname(pa.Host)
	if err != nil {
		return err
	}
	if net.ParseIP(hostname) == nil {
		return fmt.Errorf("dns bootstrap host is only support ip address")
	}

	return nil
}

func GetDNSHostname(host string) (string, error) {
	if !strings.Contains(host, "://") {
		if len(strings.Split(host, ":")) > 2 && !strings.Contains(host, "[") {
			host = "[" + host + "]"
		}
		host = "//" + host
	}

	uri, err := url.Parse(host)
	if err != nil {
		return "", fmt.Errorf("dns bootstrap host is only support ip address: %w", err)
	}

	return uri.Hostname(), nil
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
