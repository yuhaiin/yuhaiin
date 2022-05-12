package config

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type iconfig struct {
	config.UnimplementedConfigDaoServer
	current *config.Setting
	path    string

	os []Observer

	lock sync.RWMutex
}

func NewConfig(dir string) *iconfig {
	c := load(dir)
	cf := &iconfig{current: c, path: dir}
	return cf
}

func (c *iconfig) Load(context.Context, *emptypb.Empty) (*config.Setting, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.current, nil
}

func (c *iconfig) Save(_ context.Context, s *config.Setting) (*emptypb.Empty, error) {
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

type Observer interface {
	Update(*config.Setting)
}

func (c *iconfig) AddObserver(o Observer) {
	if o == nil {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	c.os = append(c.os, o)
	o.Update(c.current)
}

type wrap struct {
	u func(s *config.Setting)
}

func (w *wrap) Update(s *config.Setting) {
	w.u(s)
}

func WrapUpdate(u func(*config.Setting)) Observer {
	return &wrap{u}
}

func load(path string) *config.Setting {
	pa := &config.Setting{}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("read config file failed: %v\n", err)
		data = []byte{'{', '}'}
	}

	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, pa)
	if err != nil {
		log.Printf("unmarshal config file failed: %v\n", err)
	}

	if pa.SystemProxy == nil {
		pa.SystemProxy = &config.SystemProxy{
			Http:   true,
			Socks5: false,
			// linux system set socks5 will make firfox websocket can't connect
			// https://askubuntu.com/questions/890274/slack-desktop-client-on-16-04-behind-proxy-server
		}
	}

	if pa.Bypass == nil {
		pa.Bypass = &config.Bypass{
			Enabled:    true,
			BypassFile: filepath.Join(filepath.Dir(path), "yuhaiin.conf"),
		}
	}

	if pa.Dns == nil {
		pa.Dns = &config.DnsSetting{}
	}

	if pa.Dns.Local == nil {
		pa.Dns.Local = &config.Dns{
			Host: "223.5.5.5",
			Type: config.Dns_doh,
		}
	}

	if pa.Dns.Remote == nil {
		pa.Dns.Remote = &config.Dns{
			Host:   "cloudflare-dns.com",
			Type:   config.Dns_doh,
			Proxy:  false,
			Subnet: "0.0.0.0/32",
		}
	}

	if pa.Dns.Bootstrap == nil {
		pa.Dns.Bootstrap = &config.Dns{Host: "8.8.8.8:53", Type: config.Dns_udp}
	}

	if pa.Server == nil || pa.Server.Servers == nil {
		pa.Server = &config.Server{
			Servers: map[string]*config.ServerProtocol{
				"http": {
					Name:     "http",
					Protocol: &config.ServerProtocol_Http{Http: &config.Http{Host: "127.0.0.1:8188"}},
				},
				"socks5": {
					Name:     "socks5",
					Protocol: &config.ServerProtocol_Socks5{Socks5: &config.Socks5{Host: "127.0.0.1:1080"}},
				},
				"redir": {
					Name:     "redir",
					Protocol: &config.ServerProtocol_Redir{Redir: &config.Redir{Host: "127.0.0.1:8088"}},
				},
			},
		}
	}
	return pa
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

	return ioutil.WriteFile(dir, data, os.ModePerm)
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
	if !pa.Enabled {
		return nil
	}

	_, err := os.Stat(pa.BypassFile)
	if err != nil {
		return fmt.Errorf("check bypass file stat failed: %w", err)
	}

	return nil
}

func CheckBootstrapDns(pa *config.Dns) error {
	host := pa.Host

	if !strings.Contains(host, "://") {
		if len(strings.Split(host, ":")) > 2 && !strings.Contains(host, "[") {
			host = "[" + host + "]"
		}
		host = "//" + host
	}

	uri, err := url.Parse(host)
	if err != nil {
		return fmt.Errorf("dns bootstrap host is only support ip address: %w", err)
	}

	if net.ParseIP(uri.Hostname()) == nil {
		return fmt.Errorf("dns bootstrap host is only support ip address")
	}

	return nil
}
