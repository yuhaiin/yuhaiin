package app

import (
	"context"
	"log/slog"
	"net"
	"runtime"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
)

type SettingsController struct {
	store         *plainstore.SettingsStore
	configPath    string
	logController *log.Controller
}

func NewSettingsController(store *plainstore.SettingsStore, configPath string, logController *log.Controller) *SettingsController {
	return &SettingsController{store: store, configPath: configPath, logController: logController}
}

func (c *SettingsController) Info(ctx context.Context) (contractsettings.Info, error) {
	return c.store.Info(ctx)
}

func (c *SettingsController) Load(ctx context.Context) (contractsettings.Settings, error) {
	return c.store.Load(ctx)
}

func (c *SettingsController) Save(ctx context.Context, settings contractsettings.Settings) (contractsettings.Settings, error) {
	next, err := c.store.Save(ctx, settings)
	if err != nil {
		return contractsettings.Settings{}, err
	}
	c.Apply(next)
	return next, nil
}

func (c *SettingsController) Apply(settings contractsettings.Settings) {
	if c == nil {
		return
	}
	c.logController.Set(settings.Logcat, paths.PathGenerator.Log(c.configPath))
	slog.SetDefault(slog.New(log.Default()))

	configuration.IgnoreDnsErrorLog.Store(settings.Logcat.IgnoreDNSError)
	configuration.IgnoreTimeoutErrorLog.Store(settings.Logcat.IgnoreTimeoutError)

	sysproxy.Update(systemHTTPHost(settings), systemSocks5Host(settings))

	defaultInterfaceName := settings.NetInterface
	useDefaultInterface := settings.UseDefaultInterface
	if useDefaultInterface && runtime.GOOS != "android" {
		dialer.DefaultInterfaceName = func() string { return "" }
	} else if defaultInterfaceName == "default" {
		dialer.DefaultInterfaceName = interfaces.DefaultInterfaceName
	} else {
		dialer.DefaultInterfaceName = func() string { return defaultInterfaceName }
	}

	configuration.IPv6.Store(settings.IPv6)
	if settings.Advanced.UDPBufferSize > 2048 && settings.Advanced.UDPBufferSize < 65535 {
		configuration.UDPBufferSize.Store(int(settings.Advanced.UDPBufferSize))
	}
	if settings.Advanced.RelayBufferSize > 2048 && settings.Advanced.RelayBufferSize < 65535 {
		configuration.RelayBufferSize.Store(int(settings.Advanced.RelayBufferSize))
	}
	if settings.Advanced.UDPRingbufferSize >= 100 && settings.Advanced.UDPRingbufferSize <= 5000 {
		configuration.MaxUDPUnprocessedPackets.Store(int(settings.Advanced.UDPRingbufferSize))
	}

	happyEyeballsSemaphore := settings.Advanced.HappyEyeballsSemaphore
	if int64(happyEyeballsSemaphore) != dialer.DefaultHappyEyeballsv2Dialer.Load().SemaphoreWeight() {
		if happyEyeballsSemaphore > 0 && happyEyeballsSemaphore < 10 {
			log.Warn("happyeyeballsSemaphore is less than 10, set to 10")
			happyEyeballsSemaphore = 10
		}
		log.Info("update happyeyeballs semaphore", "value", happyEyeballsSemaphore)
		dialer.DefaultHappyEyeballsv2Dialer.Store(dialer.NewDefaultHappyEyeballsv2Dialer(
			dialer.WithHappyEyeballsSemaphore[*net.TCPConn](semaphore.NewSemaphore(int64(happyEyeballsSemaphore)))))
	}
}

func systemHTTPHost(settings contractsettings.Settings) string {
	if !settings.SystemProxy.HTTP {
		return ""
	}
	return ""
}

func systemSocks5Host(settings contractsettings.Settings) string {
	if !settings.SystemProxy.Socks5 {
		return ""
	}
	return ""
}
