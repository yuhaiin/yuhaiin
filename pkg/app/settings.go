package app

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
)

type SettingsController struct {
	store         *plainstore.SettingsStore
	configPath    string
	logController *log.Controller
	origins       *managementOriginPolicy
}

func NewSettingsController(store *plainstore.SettingsStore, configPath string, logController *log.Controller) *SettingsController {
	return &SettingsController{store: store, configPath: configPath, logController: logController, origins: newManagementOriginPolicy()}
}

func (c *SettingsController) Info(ctx context.Context) (contractsettings.Info, error) {
	return c.store.Info(ctx)
}

func (c *SettingsController) Load(ctx context.Context) (contractsettings.Settings, error) {
	return c.store.Load(ctx)
}

func (c *SettingsController) Save(ctx context.Context, settings contractsettings.Settings) (contractsettings.Settings, error) {
	if err := validateTrustedOrigins(settings.TrustedOrigins); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := validateWrapSettings(settings.Wrap); err != nil {
		return contractsettings.Settings{}, err
	}
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
	c.origins.set(settings.TrustedOrigins)
	c.logController.Set(settings.Logcat, paths.PathGenerator.Log(c.configPath))
	slog.SetDefault(slog.New(log.Default()))

	configuration.IgnoreDnsErrorLog.Store(settings.Logcat.IgnoreDNSError)
	configuration.IgnoreTimeoutErrorLog.Store(settings.Logcat.IgnoreTimeoutError)

	sysproxy.Update(systemHTTPHost(settings), systemSocks5Host(settings))

	// A concrete interface name pins every outbound socket to it. "default"
	// and "use the system default" leave the choice to Egress Selection,
	// which follows the OS routing table and only binds where that is what
	// keeps sockets out of our TUN.
	configuredInterface := settings.NetInterface
	if settings.UseDefaultInterface || configuredInterface == "default" {
		configuredInterface = ""
	}
	dialer.ConfiguredInterface = func() string { return configuredInterface }

	configuration.IPv6.Store(settings.IPv6)
	setPprofEnabled(settings.Pprof)
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
			dialer.WithHappyEyeballsSemaphore[*dialer.TCPConn](semaphore.NewSemaphore(int64(happyEyeballsSemaphore)))))
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

// validateWrapSettings rejects invalid privileged defaults before saving them.
// The listener still checks cgroup delegation and socket ownership at startup.
func validateWrapSettings(config contractsettings.WrapSettings) error {
	if config.Socket != "" && !filepath.IsAbs(config.Socket) {
		return fmt.Errorf("wrap: socket path must be absolute")
	}
	if config.CgroupRoot != "" && !filepath.IsAbs(config.CgroupRoot) {
		return fmt.Errorf("wrap: cgroup root must be absolute")
	}
	if config.MaxSessions < 0 || config.MaxSessions > 128 {
		return fmt.Errorf("wrap: maxSessions must be 0..128")
	}
	if config.Timezone != "" {
		if len(config.Timezone) > 128 || strings.ContainsAny(config.Timezone, "\x00\r\n") {
			return fmt.Errorf("wrap: invalid timezone")
		}
		if _, err := time.LoadLocation(config.Timezone); err != nil {
			return fmt.Errorf("wrap: invalid timezone %q: %w", config.Timezone, err)
		}
	}
	if config.Enabled && (config.UID == 0 || config.GID == 0) {
		return fmt.Errorf("wrap: non-root UID and GID are required when enabled")
	}
	return nil
}
