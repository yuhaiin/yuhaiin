package legacyruntime

import (
	"context"
	"log/slog"
	"net"
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/chore"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
)

func NewChore(db chore.DB, configPath string, logController *log.Controller) *chore.Chore {
	return chore.NewChore(db, func(s *config.Setting) {
		ApplyConfiguration(configPath, s, logController)
	})
}

func ApplyInitialConfiguration(ctx context.Context, service *chore.Chore, configPath string, logController *log.Controller) {
	setting, err := service.LoadLegacy(ctx)
	if err == nil {
		ApplyConfiguration(configPath, setting, logController)
	}
}

func InitialFakeDNS(ctx context.Context, service *chore.Chore, fallback chore.DB) *config.FakednsConfig {
	setting, err := service.LoadLegacy(ctx)
	if err == nil {
		if config := fakednsConfigFromSetting(setting); config != nil {
			return config
		}
	}

	if fallback == nil {
		return nil
	}
	var initial *config.FakednsConfig
	if err := fallback.View(func(s *config.Setting) error {
		initial = fakednsConfigFromSetting(s)
		return nil
	}); err != nil {
		log.Warn("load initial fakedns config failed", "err", err)
	}
	return initial
}

func fakednsConfigFromSetting(s *config.Setting) *config.FakednsConfig {
	if s == nil {
		return nil
	}
	return (&config.FakednsConfig_builder{
		Enabled:       new(s.GetDns().GetFakedns()),
		Ipv4Range:     new(s.GetDns().GetFakednsIpRange()),
		Ipv6Range:     new(s.GetDns().GetFakednsIpv6Range()),
		Whitelist:     s.GetDns().GetFakednsWhitelist(),
		SkipCheckList: s.GetDns().GetFakednsSkipCheckList(),
	}).Build()
}

func ApplyConfiguration(configPath string, s *config.Setting, logController *log.Controller) {
	logController.Set(logcatContract(s.GetLogcat()), paths.PathGenerator.Log(configPath))
	slog.SetDefault(slog.New(log.Default()))

	configuration.IgnoreDnsErrorLog.Store(s.GetLogcat().GetIgnoreDnsError())
	configuration.IgnoreTimeoutErrorLog.Store(s.GetLogcat().GetIgnoreTimeoutError())

	sysproxy.Update(chore.GetSystemHttpHost(s), chore.GetSystemSocks5Host(s))

	defaultInterfaceName := s.GetNetInterface()
	useDefaultInterface := s.GetUseDefaultInterface()

	if useDefaultInterface && runtime.GOOS != "android" {
		dialer.DefaultInterfaceName = func() string { return "" }
	} else {
		if defaultInterfaceName == "default" {
			dialer.DefaultInterfaceName = interfaces.DefaultInterfaceName
		} else {
			dialer.DefaultInterfaceName = func() string { return defaultInterfaceName }
		}
	}

	configuration.IPv6.Store(s.GetIpv6())
	configuration.FakeIPEnabled.Store(s.GetDns().GetFakedns() || s.GetServer().GetHijackDnsFakeip())
	if advanced := s.GetAdvancedConfig(); advanced != nil {
		if advanced.GetUdpBufferSize() > 2048 && advanced.GetUdpBufferSize() < 65535 {
			configuration.UDPBufferSize.Store(int(advanced.GetUdpBufferSize()))
		}

		if advanced.GetRelayBufferSize() > 2048 && advanced.GetRelayBufferSize() < 65535 {
			configuration.RelayBufferSize.Store(int(advanced.GetRelayBufferSize()))
		}

		udpRingBufferSize := s.GetAdvancedConfig().GetUdpRingbufferSize()
		if udpRingBufferSize >= 100 && udpRingBufferSize <= 5000 {
			configuration.MaxUDPUnprocessedPackets.Store(int(udpRingBufferSize))
		}

		happyeyeballsSemaphore := s.GetAdvancedConfig().GetHappyeyeballsSemaphore()

		if int64(happyeyeballsSemaphore) != dialer.DefaultHappyEyeballsv2Dialer.Load().SemaphoreWeight() {
			if happyeyeballsSemaphore > 0 && happyeyeballsSemaphore < 10 {
				log.Warn("happyeyeballsSemaphore is less than 10, set to 10")
				happyeyeballsSemaphore = 10
			}

			log.Info("update happyeyeballs semaphore", "value", happyeyeballsSemaphore)

			dialer.DefaultHappyEyeballsv2Dialer.Store(dialer.NewDefaultHappyEyeballsv2Dialer(
				dialer.WithHappyEyeballsSemaphore[*net.TCPConn](semaphore.NewSemaphore(int64(happyeyeballsSemaphore)))))
		}
	}
}

func logcatContract(in *config.Logcat) contractsettings.Logcat {
	if in == nil {
		return contractsettings.Logcat{}
	}
	return contractsettings.Logcat{
		Level:              in.GetLevel().String(),
		Save:               in.GetSave(),
		IgnoreTimeoutError: in.GetIgnoreTimeoutError(),
		IgnoreDNSError:     in.GetIgnoreDnsError(),
	}
}
