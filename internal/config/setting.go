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
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// SettingDecodeJSON decode setting json to struct
func SettingDecodeJSON(dir string) (*Setting, error) {
	pa := &Setting{
		SsrPath: "",
		SystemProxy: &SystemProxy{
			Enabled: true,
			HTTP:    true,
			Socks5:  false,
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
		DNS: &DNS{
			Host:   "cloudflare-dns.com",
			DOH:    true,
			Proxy:  false,
			Subnet: "0.0.0.0/32",
		},
		LocalDNS: &DNS{
			Host: "223.5.5.5",
			DOH:  true,
		},
	}
	data, err := ioutil.ReadFile(filepath.Join(dir, "yuhaiinConfig.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return pa, SettingEnCodeJSON(pa, dir)
		}
		return pa, fmt.Errorf("read config file failed: %v", err)
	}
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, pa)
	return pa, err
}

// SettingEnCodeJSON encode setting struct to json
func SettingEnCodeJSON(pa *Setting, dir string) error {
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

type Config struct {
	UnimplementedConfigDaoServer
	current   *Setting
	old       *Setting
	path      string
	observers []Observer
	exec      map[string]WithInit

	lock     sync.RWMutex
	execlock sync.RWMutex
}

type WithInit func(*Setting) error
type Observer func(current, old *Setting)

func NewConfig(dir string, o ...WithInit) (*Config, error) {
	c, err := SettingDecodeJSON(dir)
	if err != nil {
		return nil, fmt.Errorf("decode setting failed: %v", err)
	}

	cf := &Config{current: c, old: c, path: dir, exec: make(map[string]WithInit)}
	err = cf.Exec(o...)
	if err != nil {
		return nil, err
	}

	return cf, nil
}

func (c *Config) Exec(o ...WithInit) error {
	for i := range o {
		err := o[i](c.current)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) Load(context.Context, *emptypb.Empty) (*Setting, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.current, nil
}

func (c *Config) Save(_ context.Context, s *Setting) (*emptypb.Empty, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	err := SettingEnCodeJSON(s, c.path)
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("save settings failed: %v", err)
	}

	c.old = c.current
	c.current = s

	wg := sync.WaitGroup{}
	for i := range c.observers {
		wg.Add(1)
		go func(o Observer) {
			wg.Done()
			o(c.current, c.old)
		}(c.observers[i])
	}
	wg.Wait()

	return &emptypb.Empty{}, nil
}

func (c *Config) AddObserver(o Observer) {
	if o == nil {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.observers = append(c.observers, o)
}

func (c *Config) AddExecCommand(key string, o WithInit) error {
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
