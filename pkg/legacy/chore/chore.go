package chore

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

type Chore struct {
	db     DB
	onSave func(*config.Setting)
	mu     sync.RWMutex
}

func NewChore(db DB, onSave func(*config.Setting)) *Chore {
	return &Chore{db: db, onSave: onSave}
}

func (c *Chore) Info(context.Context) (contractsettings.Info, error) { return infoContract(), nil }

func (c *Chore) Load(ctx context.Context) (contractsettings.Settings, error) {
	setting, err := c.LoadLegacy(ctx)
	if err != nil {
		return contractsettings.Settings{}, err
	}
	return settingsFromLegacy(setting), nil
}

func (c *Chore) LoadLegacy(context.Context) (*config.Setting, error) {
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

func (c *Chore) Save(ctx context.Context, s contractsettings.Settings) (contractsettings.Settings, error) {
	err := c.db.Batch(func(ss *config.Setting) error {
		ss.SetIpv6(s.IPv6)

		ss.SetUseDefaultInterface(s.UseDefaultInterface)
		ss.SetNetInterface(s.NetInterface)

		ss.SetSystemProxy(&config.SystemProxy{
			Http:   s.SystemProxy.HTTP,
			Socks5: s.SystemProxy.Socks5,
		})

		ss.SetLogcat(&config.Logcat{
			Level:              parseLogLevel(s.Logcat.Level),
			Save:               s.Logcat.Save,
			IgnoreTimeoutError: s.Logcat.IgnoreTimeoutError,
			IgnoreDnsError:     s.Logcat.IgnoreDNSError,
		})

		ss.SetAdvancedConfig(&config.AdvancedConfig{
			UdpBufferSize:          s.Advanced.UDPBufferSize,
			RelayBufferSize:        s.Advanced.RelayBufferSize,
			UdpRingbufferSize:      s.Advanced.UDPRingbufferSize,
			HappyeyeballsSemaphore: s.Advanced.HappyEyeballsSemaphore,
		})
		if ss.GetBackup() == nil {
			ss.SetBackup(&config.BackupOption{})
		}
		ss.GetBackup().SetInstanceName(s.Backup.InstanceName)
		ss.GetBackup().SetInterval(s.Backup.Interval)
		ss.GetBackup().SetLastBackupHash(s.Backup.LastBackupHash)

		if c.onSave != nil {
			c.onSave(ss)
		}
		return nil
	})
	if err != nil {
		return contractsettings.Settings{}, err
	}

	return c.Load(ctx)
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
		Platform:  new(runtime.GOOS + "/" + runtime.GOARCH),
		Compiler:  new(runtime.Compiler),
		Arch:      new(runtime.GOARCH),
		Os:        new(runtime.GOOS),
		Build_:    build,
	}).Build()
}

func infoContract() contractsettings.Info {
	info := Info()
	return contractsettings.Info{
		Version:   info.GetVersion(),
		Commit:    info.GetCommit(),
		BuildTime: info.GetBuildTime(),
		GoVersion: info.GetGoVersion(),
		Arch:      info.GetArch(),
		Platform:  info.GetPlatform(),
		OS:        info.GetOs(),
		Compiler:  info.GetCompiler(),
		Build:     info.GetBuild_(),
	}
}

func settingsFromLegacy(in *config.Setting) contractsettings.Settings {
	var out contractsettings.Settings
	if in == nil {
		return out
	}
	out.IPv6 = in.GetIpv6()
	out.UseDefaultInterface = in.GetUseDefaultInterface()
	out.NetInterface = in.GetNetInterface()
	if v := in.GetSystemProxy(); v != nil {
		out.SystemProxy = contractsettings.SystemProxy{
			HTTP:   v.GetHttp(),
			Socks5: v.GetSocks5(),
		}
	}
	if v := in.GetLogcat(); v != nil {
		out.Logcat = contractsettings.Logcat{
			Level:              v.GetLevel().String(),
			Save:               v.GetSave(),
			IgnoreTimeoutError: v.GetIgnoreTimeoutError(),
			IgnoreDNSError:     v.GetIgnoreDnsError(),
		}
	}
	if v := in.GetAdvancedConfig(); v != nil {
		out.Advanced = contractsettings.AdvancedConfig{
			UDPBufferSize:          v.GetUdpBufferSize(),
			RelayBufferSize:        v.GetRelayBufferSize(),
			UDPRingbufferSize:      v.GetUdpRingbufferSize(),
			HappyEyeballsSemaphore: v.GetHappyeyeballsSemaphore(),
		}
	}
	if v := in.GetBackup(); v != nil {
		out.Backup = contractsettings.BackupReference{
			InstanceName:   v.GetInstanceName(),
			Interval:       v.GetInterval(),
			LastBackupHash: v.GetLastBackupHash(),
		}
	}
	return out
}

func parseLogLevel(level string) config.LogLevel {
	switch level {
	case "debug", "verbose", "LogLevel_debug", "LogLevel_verbose":
		return config.LogLevel_debug
	case "warning", "warn", "LogLevel_warning":
		return config.LogLevel_warning
	case "error", "fatal", "LogLevel_error", "LogLevel_fatal":
		return config.LogLevel_error
	default:
		return config.LogLevel_info
	}
}
