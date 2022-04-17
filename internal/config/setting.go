package config

import (
	context "context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// settingDecodeJSON decode setting json to struct
func settingDecodeJSON(dir string) *config.Setting {
	pa := &config.Setting{
		SystemProxy: &config.SystemProxy{
			Http:   true,
			Socks5: false,
			// linux system set socks5 will make firfox websocket can't connect
			// https://askubuntu.com/questions/890274/slack-desktop-client-on-16-04-behind-proxy-server
		},
		Bypass: &config.Bypass{
			Enabled:    true,
			BypassFile: filepath.Join(filepath.Dir(dir), "yuhaiin.conf"),
		},

		Dns: &config.DnsSetting{
			Remote: &config.Dns{
				Host:   "cloudflare-dns.com",
				Type:   config.Dns_doh,
				Proxy:  false,
				Subnet: "0.0.0.0/32",
			},
			Local: &config.Dns{
				Host: "223.5.5.5",
				Type: config.Dns_doh,
			},
		},
	}
	data, err := ioutil.ReadFile(dir)
	if err != nil {
		log.Printf("read config file failed: %v\n", err)
		data = []byte{'{', '}'}
	}

	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, pa)
	if err != nil {
		log.Printf("unmarshal config file failed: %v\n", err)
	}

	if pa.Server == nil || pa.Server.Servers == nil {
		pa.Server = &config.Server{
			Servers: map[string]*config.ServerProtocol{
				"http": {
					Name: "http",
					Hash: "http",
					Protocol: &config.ServerProtocol_Http{
						Http: &config.Http{
							Host: "127.0.0.1:8188",
						},
					},
				},
				"socks5": {
					Name: "socks5",
					Hash: "socks5",
					Protocol: &config.ServerProtocol_Socks5{
						Socks5: &config.Socks5{
							Host: "127.0.0.1:1080",
						},
					},
				},
				"redir": {
					Name: "redir",
					Hash: "redir",
					Protocol: &config.ServerProtocol_Redir{
						Redir: &config.Redir{
							Host: "127.0.0.1:8088",
						},
					},
				},
			},
		}
	}
	return pa
}

// settingEnCodeJSON encode setting struct to json
func settingEnCodeJSON(pa *config.Setting, dir string) error {
	_, err := os.Stat(dir)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return fmt.Errorf("make dir failed: %v", err)
		}
	}

	data, err := protojson.MarshalOptions{Multiline: true, Indent: "\t"}.Marshal(pa)
	if err != nil {
		return fmt.Errorf("marshal setting failed: %v", err)
	}

	return ioutil.WriteFile(filepath.Join(dir, "yuhaiinConfig.json"), data, os.ModePerm)
}

type observer struct {
	diff func(current, old *config.Setting) bool
	exec func(current *config.Setting)
}
type Config struct {
	config.UnimplementedConfigDaoServer
	current *config.Setting
	old     *config.Setting
	path    string
	exec    map[string]InitFunc

	os []observer

	lock     sync.RWMutex
	execlock sync.RWMutex
}

type InitFunc func(*config.Setting) error

func NewConfig(dir string) *Config {
	c := settingDecodeJSON(dir)
	cf := &Config{current: c, old: c, path: dir, exec: make(map[string]InitFunc)}
	return cf
}

func (c *Config) Load(context.Context, *emptypb.Empty) (*config.Setting, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.current, nil
}

func (c *Config) Save(_ context.Context, s *config.Setting) (*emptypb.Empty, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, v := range s.Server.Servers {
		refreshHash(v)
	}
	err := settingEnCodeJSON(s, c.path)
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("save settings failed: %v", err)
	}

	c.old = proto.Clone(c.current).(*config.Setting)
	c.current = proto.Clone(s).(*config.Setting)

	wg := sync.WaitGroup{}
	for i := range c.os {
		wg.Add(1)
		go func(o observer) {
			wg.Done()
			if o.diff(proto.Clone(c.current).(*config.Setting), proto.Clone(c.old).(*config.Setting)) {
				o.exec(proto.Clone(c.current).(*config.Setting))
			}
		}(c.os[i])
	}
	wg.Wait()

	return &emptypb.Empty{}, nil
}

func refreshHash(p *config.ServerProtocol) {
	p.Hash = ""
	z := sha256.Sum256([]byte(p.String()))
	p.Hash = hex.EncodeToString(z[:])
}

func (c *Config) AddObserver(diff func(current, old *config.Setting) bool, exec func(current *config.Setting)) {
	if diff == nil || exec == nil {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	c.os = append(c.os, observer{diff, exec})
}

type ConfigObserver interface {
	AddObserverAndExec(func(current, old *config.Setting) bool, func(current *config.Setting))
	AddExecCommand(string, InitFunc)
}

func (c *Config) AddObserverAndExec(diff func(current, old *config.Setting) bool, exec func(current *config.Setting)) {
	c.AddObserver(diff, exec)
	exec(c.current)
}

func (c *Config) AddExecCommand(key string, o InitFunc) error {
	if o == nil {
		return nil
	}

	c.execlock.Lock()
	defer c.execlock.Unlock()
	_, ok := c.exec[key]
	if ok {
		return fmt.Errorf("already exist command %v", key)
	}

	c.exec[key] = o
	return nil
}

func (c *Config) ExecCommand(key string) error {
	c.execlock.RLock()
	defer c.execlock.RUnlock()
	e, ok := c.exec[key]
	if !ok {
		return fmt.Errorf("command %v is not exist", key)
	}

	return e(c.current)
}

func (c *Config) DeleteExecCommand(key string) {
	c.execlock.Lock()
	defer c.execlock.Unlock()
	delete(c.exec, key)
}
