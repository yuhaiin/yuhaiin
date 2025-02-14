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
	if c.db.Data.GetBypass().GetBypassFile() != "" {
		c.db.Data.GetBypass().SetRemoteRules(append(c.db.Data.GetBypass().GetRemoteRules(), bypass.RemoteRule_builder{
			Enabled: proto.Bool(true),
			Name:    proto.String("old_bypass_file"),
			File: bypass.RemoteRuleFile_builder{
				Path: proto.String(c.db.Data.GetBypass().GetBypassFile()),
			}.Build(),
		}.Build()))

		c.db.Data.GetBypass().SetBypassFile("")
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

	return (&config.Info_builder{
		Version:   proto.String(version.Version),
		Commit:    proto.String(version.GitCommit),
		BuildTime: proto.String(version.BuildTime),
		GoVersion: proto.String(runtime.Version()),
		Platform:  proto.String(runtime.GOOS + "/" + runtime.GOARCH),
		Compiler:  proto.String(runtime.Compiler),
		Arch:      proto.String(runtime.GOARCH),
		Os:        proto.String(runtime.GOOS),
		Build_:    build,
	}).Build()
}

func (c *setting) View(f ...func(*config.Setting) error) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, v := range f {
		if err := v(c.db.Data); err != nil {
			return err
		}
	}

	return nil
}

func (c *setting) Load(context.Context, *emptypb.Empty) (*config.Setting, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return config.Setting_builder{
		AdvancedConfig:             c.db.Data.GetAdvancedConfig(),
		UseDefaultInterface:        proto.Bool(c.db.Data.GetUseDefaultInterface()),
		Ipv6:                       proto.Bool(c.db.Data.GetIpv6()),
		Ipv6LocalAddrPreferUnicast: proto.Bool(c.db.Data.GetIpv6LocalAddrPreferUnicast()),
		Logcat:                     c.db.Data.GetLogcat(),
		NetInterface:               proto.String(c.db.Data.GetNetInterface()),
		SystemProxy:                c.db.Data.GetSystemProxy(),
		Server: listener.InboundConfig_builder{
			HijackDns:       proto.Bool(c.db.Data.GetServer().GetHijackDns()),
			HijackDnsFakeip: proto.Bool(c.db.Data.GetServer().GetHijackDnsFakeip()),
			Sniff:           c.db.Data.GetServer().GetSniff(),
		}.Build(),
		Platform: c.db.Data.GetPlatform(),
	}.Build(), nil
}

func (c *setting) Save(ctx context.Context, s *config.Setting) (*emptypb.Empty, error) {
	err := c.Batch(func(ss *config.Setting) error {
		ss.SetIpv6(s.GetIpv6())
		ss.SetUseDefaultInterface(s.GetUseDefaultInterface())
		ss.SetNetInterface(s.GetNetInterface())
		ss.SetIpv6LocalAddrPreferUnicast(s.GetIpv6LocalAddrPreferUnicast())
		ss.SetLogcat(s.GetLogcat())
		ss.SetSystemProxy(s.GetSystemProxy())
		ss.GetServer().SetHijackDns(s.GetServer().GetHijackDns())
		ss.GetServer().SetHijackDnsFakeip(s.GetServer().GetHijackDnsFakeip())
		ss.GetServer().SetSniff(s.GetServer().GetSniff())
		ss.SetAdvancedConfig(s.GetAdvancedConfig())
		return nil
	})

	return &emptypb.Empty{}, err
}

func (c *setting) AddObserver(o Observer) {
	if o == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.os = append(c.os, o)
	o.Update(proto.Clone(c.db.Data).(*config.Setting))
}

func (c *setting) Batch(f ...func(*config.Setting) error) error {
	if len(f) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cf := proto.Clone(c.db.Data).(*config.Setting)
	for i := range f {
		if err := f[i](cf); err != nil {
			return err
		}
	}

	if proto.Equal(c.db.Data, cf) {
		return nil
	}

	c.db.Data = cf

	if err := c.db.Save(); err != nil {
		return fmt.Errorf("save settings failed: %w", err)
	}

	for i := range c.os {
		c.os[i].Update(proto.Clone(cf).(*config.Setting))
	}

	return nil
}

func (c *setting) Dir() string { return c.db.Dir() }
