package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
)

type SettingsStore struct {
	db *sql.DB
}

func NewSettingsStore(db *sql.DB) *SettingsStore {
	return &SettingsStore{db: db}
}

func (s *SettingsStore) Info(context.Context) (contractsettings.Info, error) {
	var build []string
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, v := range info.Settings {
			build = append(build, fmt.Sprintf("%s=%s", v.Key, v.Value))
		}
	}
	return contractsettings.Info{
		Version:   version.Version,
		Commit:    version.GitCommit,
		BuildTime: version.BuildTime,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Compiler:  runtime.Compiler,
		Arch:      runtime.GOARCH,
		OS:        runtime.GOOS,
		Build:     build,
	}, nil
}

func (s *SettingsStore) Load(ctx context.Context) (contractsettings.Settings, error) {
	if s == nil || s.db == nil {
		return contractsettings.Settings{}, errors.New("settings store database is nil")
	}
	// Pprof used to be enabled unless DISABLED_PPROF was set. Keep that default
	// for existing installations which do not yet have a persisted setting.
	out := contractsettings.Settings{Pprof: true}
	if err := s.load(ctx, "general", "ipv6", &out.IPv6); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "general", "use_default_interface", &out.UseDefaultInterface); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "general", "net_interface", &out.NetInterface); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "general", "pprof", &out.Pprof); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "system_proxy", "http", &out.SystemProxy.HTTP); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "system_proxy", "socks5", &out.SystemProxy.Socks5); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.loadLogLevel(ctx, &out.Logcat.Level); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "logcat", "save", &out.Logcat.Save); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "logcat", "ignore_dns_error", &out.Logcat.IgnoreDNSError); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "logcat", "ignore_timeout_error", &out.Logcat.IgnoreTimeoutError); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "advanced", "udp_buffer_size", &out.Advanced.UDPBufferSize); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "advanced", "relay_buffer_size", &out.Advanced.RelayBufferSize); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "advanced", "udp_ringbuffer_size", &out.Advanced.UDPRingbufferSize); err != nil {
		return contractsettings.Settings{}, err
	}
	if err := s.load(ctx, "advanced", "happyeyeballs_semaphore", &out.Advanced.HappyEyeballsSemaphore); err != nil {
		return contractsettings.Settings{}, err
	}
	return out, nil
}

func (s *SettingsStore) Save(ctx context.Context, settings contractsettings.Settings) (contractsettings.Settings, error) {
	if s == nil || s.db == nil {
		return contractsettings.Settings{}, errors.New("settings store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contractsettings.Settings{}, fmt.Errorf("begin settings transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	values := []struct {
		section string
		key     string
		value   any
	}{
		{"general", "ipv6", settings.IPv6},
		{"general", "use_default_interface", settings.UseDefaultInterface},
		{"general", "net_interface", settings.NetInterface},
		{"general", "pprof", settings.Pprof},
		{"system_proxy", "http", settings.SystemProxy.HTTP},
		{"system_proxy", "socks5", settings.SystemProxy.Socks5},
		{"logcat", "level", logLevelCode(settings.Logcat.Level)},
		{"logcat", "save", settings.Logcat.Save},
		{"logcat", "ignore_dns_error", settings.Logcat.IgnoreDNSError},
		{"logcat", "ignore_timeout_error", settings.Logcat.IgnoreTimeoutError},
		{"advanced", "udp_buffer_size", settings.Advanced.UDPBufferSize},
		{"advanced", "relay_buffer_size", settings.Advanced.RelayBufferSize},
		{"advanced", "udp_ringbuffer_size", settings.Advanced.UDPRingbufferSize},
		{"advanced", "happyeyeballs_semaphore", settings.Advanced.HappyEyeballsSemaphore},
	}
	for _, value := range values {
		if err := saveSettingsKV(ctx, tx, value.section, value.key, value.value, now); err != nil {
			return contractsettings.Settings{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return contractsettings.Settings{}, fmt.Errorf("commit settings transaction failed: %w", err)
	}
	return s.Load(ctx)
}

func (s *SettingsStore) load(ctx context.Context, section, key string, out any) error {
	var data string
	err := s.db.QueryRowContext(ctx, `
		SELECT value_json
		FROM settings_kv
		WHERE section = ? AND key = ?
	`, section, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("query settings %s.%s failed: %w", section, key, err)
	}
	if err := json.Unmarshal([]byte(data), out); err != nil {
		return fmt.Errorf("decode settings %s.%s failed: %w", section, key, err)
	}
	return nil
}

func (s *SettingsStore) loadLogLevel(ctx context.Context, out *string) error {
	var code int32
	if err := s.load(ctx, "logcat", "level", &code); err != nil {
		return err
	}
	*out = logLevelString(code)
	return nil
}

func logLevelString(code int32) string {
	switch code {
	case 0:
		return "verbose"
	case 1:
		return "debug"
	case 2:
		return "info"
	case 3:
		return "warning"
	case 4:
		return "error"
	case 5:
		return "fatal"
	default:
		return "info"
	}
}

func logLevelCode(level string) int32 {
	switch level {
	case "verbose":
		return 0
	case "debug":
		return 1
	case "warning", "warn":
		return 3
	case "error":
		return 4
	case "fatal":
		return 5
	default:
		return 2
	}
}
