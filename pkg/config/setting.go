package config

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Setting interface {
	config.DB
	gc.ConfigServiceServer
	AddObserver(Observer)

	View(f func(*config.Setting) error) error
	Update(f func(*config.Setting) error) error
}

type Observer interface {
	Update(*config.Setting)
}

type ObserverFunc func(*config.Setting)

func (o ObserverFunc) Update(s *config.Setting) { o(s) }

type setting struct {
	gc.UnimplementedConfigServiceServer

	db *jsondb.DB[*config.Setting]

	os []Observer

	mu sync.RWMutex
}

func NewConfig(path string) Setting {
	s := &setting{db: jsondb.Open(path, DefaultSetting(path))}
	s.migrate()
	return s
}

func (c *setting) migrate() {
	if c.db.Data.Bypass.BypassFile != "" {
		c.db.Data.Bypass.RemoteRules = append(c.db.Data.Bypass.RemoteRules, &bypass.RemoteRule{
			Enabled: true,
			Name:    "old_bypass_file",
			Object: &bypass.RemoteRule_File{
				File: &bypass.RemoteRuleFile{
					Path: c.db.Data.Bypass.BypassFile,
				},
			},
		})

		c.db.Data.Bypass.BypassFile = ""
	}
}

func (c *setting) Info(context.Context, *emptypb.Empty) (*config.Info, error) { return Info(), nil }

func Info() *config.Info {
	var build []string
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, v := range info.Settings {
			build = append(build, fmt.Sprintf("%s=%s", v.Key, v.Value))
		}
	}

	return &config.Info{
		Version:   version.Version,
		Commit:    version.GitCommit,
		BuildTime: version.BuildTime,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Compiler:  runtime.Compiler,
		Arch:      runtime.GOARCH,
		Os:        runtime.GOOS,
		Build:     build,
	}
}

func (c *setting) View(f func(*config.Setting) error) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return f(c.db.Data)
}

func (c *setting) Update(f func(*config.Setting) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ss := c.db.Data
	if err := f(ss); err != nil {
		return err
	}

	_, err := c.save(context.Background(), ss)
	return err
}

func (c *setting) Load(context.Context, *emptypb.Empty) (*config.Setting, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return &config.Setting{
		Dns:                        c.db.Data.Dns,
		Ipv6:                       c.db.Data.Ipv6,
		Ipv6LocalAddrPreferUnicast: c.db.Data.Ipv6LocalAddrPreferUnicast,
		Logcat:                     c.db.Data.Logcat,
		NetInterface:               c.db.Data.NetInterface,
		SystemProxy:                c.db.Data.SystemProxy,
		Server: &listener.InboundConfig{
			HijackDns:       c.db.Data.Server.HijackDns,
			HijackDnsFakeip: c.db.Data.Server.HijackDnsFakeip,
			Sniff:           c.db.Data.Server.Sniff,
		},
		Platform: c.db.Data.Platform,
	}, nil
}

func (c *setting) Save(ctx context.Context, s *config.Setting) (*emptypb.Empty, error) {
	err := c.Update(func(ss *config.Setting) error {
		ss.Dns = s.Dns
		ss.Ipv6 = s.Ipv6
		ss.Ipv6LocalAddrPreferUnicast = s.Ipv6LocalAddrPreferUnicast
		ss.Logcat = s.Logcat
		ss.NetInterface = s.NetInterface
		ss.SystemProxy = s.SystemProxy
		ss.Server.HijackDns = s.Server.HijackDns
		ss.Server.HijackDnsFakeip = s.Server.HijackDnsFakeip
		ss.Server.Sniff = s.Server.Sniff

		return nil
	})

	return &emptypb.Empty{}, err
}

func (c *setting) save(_ context.Context, s *config.Setting) (*emptypb.Empty, error) {
	x := proto.Clone(s).(*config.Setting)
	x.Bypass = c.db.Data.Bypass
	c.db.Data = x

	if err := c.db.Save(); err != nil {
		return &emptypb.Empty{}, fmt.Errorf("save settings failed: %w", err)
	}

	wg := sync.WaitGroup{}
	for i := range c.os {
		wg.Add(1)
		go func(o Observer) {
			defer wg.Done()
			o.Update(proto.Clone(c.db.Data).(*config.Setting))
		}(c.os[i])
	}
	wg.Wait()

	return &emptypb.Empty{}, nil
}

func (c *setting) AddObserver(o Observer) {
	if o == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.os = append(c.os, o)
	o.Update(c.db.Data)
}

func (c *setting) Batch(f ...func(*config.Setting) error) error {
	if len(f) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	config := proto.Clone(c.db.Data).(*config.Setting)
	for i := range f {
		if err := f[i](config); err != nil {
			return err
		}
	}

	if proto.Equal(c.db.Data, config) {
		return nil
	}

	c.db.Data = config

	return c.db.Save()
}

func (c *setting) Dir() string { return c.db.Dir() }
