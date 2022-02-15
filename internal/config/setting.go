package config

import (
	context "context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// settingDecodeJSON decode setting json to struct
func settingDecodeJSON(dir string) (*Setting, error) {
	pa := &Setting{
		SystemProxy: &SystemProxy{
			HTTP:   true,
			Socks5: false,
			// linux system set socks5 will make firfox websocket can't connect
			// https://askubuntu.com/questions/890274/slack-desktop-client-on-16-04-behind-proxy-server
		},
		Bypass: &Bypass{
			Enabled:    true,
			BypassFile: path.Join(dir, "yuhaiin.conf"),
		},
		Proxy: &Proxy{
			HTTP:   "127.0.0.1:8188",
			Socks5: "127.0.0.1:1080",
			Redir:  "127.0.0.1:8088",
		},
		Dns: &DnsSetting{
			Remote: &DNS{
				Host:   "cloudflare-dns.com",
				Type:   DNS_doh,
				Proxy:  false,
				Subnet: "0.0.0.0/32",
			},
			Local: &DNS{
				Host: "223.5.5.5",
				Type: DNS_doh,
			},
		},
	}
	data, err := ioutil.ReadFile(filepath.Join(dir, "yuhaiinConfig.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return pa, settingEnCodeJSON(pa, dir)
		}
		return pa, fmt.Errorf("read config file failed: %v", err)
	}
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, pa)
	return pa, err
}

// settingEnCodeJSON encode setting struct to json
func settingEnCodeJSON(pa *Setting, dir string) error {
	_, err := os.Stat(filepath.Join(dir, "yuhaiinConfig.json"))
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
	diff func(current, old *Setting) bool
	exec func(current *Setting)
}
type Config struct {
	UnimplementedConfigDaoServer
	current *Setting
	old     *Setting
	path    string
	exec    map[string]InitFunc

	os []observer

	lock     sync.RWMutex
	execlock sync.RWMutex
}

type InitFunc func(*Setting) error

func NewConfig(dir string) (*Config, error) {
	c, err := settingDecodeJSON(dir)
	if err != nil {
		return nil, fmt.Errorf("decode setting failed: %v", err)
	}

	cf := &Config{current: c, old: c, path: dir, exec: make(map[string]InitFunc)}

	return cf, nil
}

func (c *Config) Load(context.Context, *emptypb.Empty) (*Setting, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.current, nil
}

func (c *Config) Save(_ context.Context, s *Setting) (*emptypb.Empty, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	err := settingEnCodeJSON(s, c.path)
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("save settings failed: %v", err)
	}

	c.old = proto.Clone(c.current).(*Setting)
	c.current = proto.Clone(s).(*Setting)

	wg := sync.WaitGroup{}
	for i := range c.os {
		wg.Add(1)
		go func(o observer) {
			wg.Done()
			if o.diff(proto.Clone(c.current).(*Setting), proto.Clone(c.old).(*Setting)) {
				o.exec(proto.Clone(c.current).(*Setting))
			}
		}(c.os[i])
	}
	wg.Wait()

	return &emptypb.Empty{}, nil
}

func (c *Config) AddObserver(diff func(current, old *Setting) bool, exec func(current *Setting)) {
	if diff == nil || exec == nil {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	c.os = append(c.os, observer{diff, exec})
}

func (c *Config) AddObserverAndExec(diff func(current, old *Setting) bool, exec func(current *Setting)) {
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
