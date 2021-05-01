package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"
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
	current   *Setting
	old       *Setting
	path      string
	observers []Observer

	lock sync.Mutex
}

type Observer func(current, old *Setting)

func NewConfig(dir string) (*Config, error) {
	c, err := SettingDecodeJSON(dir)
	if err != nil {
		return nil, fmt.Errorf("decode setting failed: %v", err)
	}

	return &Config{
		current: c,
		old:     c,
		path:    dir,
	}, nil
}

func (c *Config) GetSetting() *Setting {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.current
}

func (c *Config) AddObserver(o Observer) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.observers = append(c.observers, o)
}

func (c *Config) Apply(s *Setting) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	err := SettingEnCodeJSON(s, c.path)
	if err != nil {
		return fmt.Errorf("save settings failed: %v", err)
	}

	c.old = c.current
	c.current = s

	for i := range c.observers {
		c.observers[i](c.current, c.old)
	}

	return nil
}
