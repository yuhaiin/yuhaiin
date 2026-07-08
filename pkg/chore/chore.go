package chore

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	schemaapi "github.com/Asutorufa/yuhaiin/pkg/schema/api"
	"github.com/Asutorufa/yuhaiin/pkg/schema/config"
)

type Chore struct {
	db     DB
	onSave func(*config.Setting)
	mu     sync.RWMutex
}

func NewChore(db DB, onSave func(*config.Setting)) *Chore {
	return &Chore{db: db, onSave: onSave}
}

func (c *Chore) Info(context.Context, *schemaapi.Empty) (*config.Info, error) { return Info(), nil }

func (c *Chore) Load(context.Context, *schemaapi.Empty) (*config.Setting, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var setting *config.Setting

	err := c.db.View(func(s *config.Setting) error {
		if !s.HasAdvancedConfig() {
			s.SetAdvancedConfig(config.AdvancedConfig_builder{
				UdpBufferSize:     new(int32(configuration.UDPBufferSize.Load())),
				RelayBufferSize:   new(int32(configuration.RelayBufferSize.Load())),
				UdpRingbufferSize: new(int32(configuration.MaxUDPUnprocessedPackets.Load())),
			}.Build())
		}

		if !s.HasLogcat() {
			s.SetLogcat(config.Logcat_builder{
				Save:               new(false),
				Level:              config.LogLevel_info.Enum(),
				IgnoreDnsError:     new(configuration.IgnoreDnsErrorLog.Load()),
				IgnoreTimeoutError: new(configuration.IgnoreTimeoutErrorLog.Load()),
			}.Build())
		} else if !s.GetLogcat().HasIgnoreDnsError() {
			s.GetLogcat().SetIgnoreDnsError(false)
		} else if !s.GetLogcat().HasIgnoreTimeoutError() {
			s.GetLogcat().SetIgnoreTimeoutError(false)
		}

		if !s.HasSystemProxy() {
			s.SetSystemProxy(config.SystemProxy_builder{
				Http:   new(false),
				Socks5: new(false),
			}.Build())
		}

		setting = config.Setting_builder{
			AdvancedConfig:      s.GetAdvancedConfig(),
			UseDefaultInterface: new(s.GetUseDefaultInterface()),
			NetInterface:        new(s.GetNetInterface()),
			Ipv6:                new(s.GetIpv6()),
			Logcat:              s.GetLogcat(),
			SystemProxy:         s.GetSystemProxy(),
			Platform:            s.GetPlatform(),
		}.Build()

		return nil
	})

	return setting, err

}

func (c *Chore) Save(ctx context.Context, s *config.Setting) (*schemaapi.Empty, error) {
	err := c.db.Batch(func(ss *config.Setting) error {
		ss.SetIpv6(s.GetIpv6())

		ss.SetUseDefaultInterface(s.GetUseDefaultInterface())
		ss.SetNetInterface(s.GetNetInterface())

		ss.SetSystemProxy(s.GetSystemProxy())

		ss.SetLogcat(s.GetLogcat())

		ss.SetAdvancedConfig(s.GetAdvancedConfig())

		c.onSave(ss)
		return nil
	})

	return &schemaapi.Empty{}, err
}

func Info() *config.Info {
	var build []string
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, v := range info.Settings {
			build = append(build, fmt.Sprintf("%s=%s", v.Key, v.Value))
		}
	}

	return (&config.Info_builder{
		Version:   new(version.Version),
		Commit:    new(version.GitCommit),
		BuildTime: new(version.BuildTime),
		GoVersion: new(runtime.Version()),
		Platform:  ptr(runtime.GOOS + "/" + runtime.GOARCH),
		Compiler:  ptr(runtime.Compiler),
		Arch:      ptr(runtime.GOARCH),
		Os:        ptr(runtime.GOOS),
		Build_:    build,
	}).Build()
}

func ptr[T any](v T) *T { return &v }
