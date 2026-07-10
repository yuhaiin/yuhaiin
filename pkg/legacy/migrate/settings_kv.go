package migrate

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"

	legacyconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

const legacySettingsKVNormalizationDoneKey = "legacy_settings_kv_normalization_done"

type canonicalRouteRefreshConfig struct {
	RefreshInterval uint64 `json:"refresh_interval"`
	LastRefreshTime uint64 `json:"last_refresh_time"`
	Error           string `json:"error"`
}

// NormalizeLegacySettingsKV rewrites every old scalar JSON representation
// consumed by the plain stores before the legacy state migrator reads it.
func NormalizeLegacySettingsKV(ctx context.Context, db *sql.DB) error {
	done, err := legacyMetadata(ctx, db, legacySettingsKVNormalizationDoneKey)
	if err != nil || done == "1" {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, value := range []struct{ section, key string }{
		{"general", "ipv6"},
		{"general", "use_default_interface"},
		{"system_proxy", "http"},
		{"system_proxy", "socks5"},
		{"logcat", "save"},
		{"logcat", "ignore_dns_error"},
		{"logcat", "ignore_timeout_error"},
	} {
		if err := normalizeSettingsKVBool(ctx, tx, value.section, value.key); err != nil {
			return err
		}
	}
	for _, value := range []struct{ section, key string }{
		{"advanced", "udp_buffer_size"},
		{"advanced", "relay_buffer_size"},
		{"advanced", "udp_ringbuffer_size"},
		{"advanced", "happyeyeballs_semaphore"},
	} {
		if err := normalizeSettingsKVInt32(ctx, tx, value.section, value.key, false); err != nil {
			return err
		}
	}
	if err := normalizeSettingsKVInt32(ctx, tx, "logcat", "level", true); err != nil {
		return err
	}
	if err := normalizeRouteRefreshConfig(ctx, tx); err != nil {
		return err
	}
	if err := setLegacyMetadataTx(ctx, tx, map[string]string{legacySettingsKVNormalizationDoneKey: "1"}); err != nil {
		return err
	}
	return tx.Commit()
}

func normalizeSettingsKVBool(ctx context.Context, tx *sql.Tx, section, key string) error {
	data, ok, err := loadSettingsKV(ctx, tx, section, key)
	if err != nil || !ok {
		return err
	}
	var value bool
	if err := json.Unmarshal([]byte(data), &value); err != nil {
		var text string
		if stringErr := json.Unmarshal([]byte(data), &text); stringErr != nil {
			return fmt.Errorf("decode legacy %s.%s bool: %w", section, key, err)
		}
		switch strings.ToLower(strings.TrimSpace(text)) {
		case "true", "1":
			value = true
		case "false", "0", "":
			value = false
		default:
			return fmt.Errorf("decode legacy %s.%s bool: unknown value %q", section, key, text)
		}
	}
	return saveCanonicalSettingsKV(ctx, tx, section, key, value)
}

func normalizeSettingsKVInt32(ctx context.Context, tx *sql.Tx, section, key string, logLevel bool) error {
	data, ok, err := loadSettingsKV(ctx, tx, section, key)
	if err != nil || !ok {
		return err
	}
	var value int32
	if err := json.Unmarshal([]byte(data), &value); err != nil {
		var text string
		if stringErr := json.Unmarshal([]byte(data), &text); stringErr != nil {
			return fmt.Errorf("decode legacy %s.%s integer: %w", section, key, err)
		}
		if logLevel {
			if code, ok := legacyLogLevel(text); ok {
				value = code
			} else {
				parsed, parseErr := strconv.ParseInt(strings.TrimSpace(text), 10, 32)
				if parseErr != nil {
					return fmt.Errorf("decode legacy logcat.level %q: %w", text, parseErr)
				}
				value = int32(parsed)
			}
		} else {
			parsed, parseErr := strconv.ParseInt(strings.TrimSpace(text), 10, 32)
			if parseErr != nil {
				return fmt.Errorf("decode legacy %s.%s integer %q: %w", section, key, text, parseErr)
			}
			value = int32(parsed)
		}
	}
	return saveCanonicalSettingsKV(ctx, tx, section, key, value)
}

func legacyLogLevel(value string) (int32, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verbose":
		return 0, true
	case "debug":
		return 1, true
	case "info":
		return 2, true
	case "warning", "warn":
		return 3, true
	case "error":
		return 4, true
	case "fatal":
		return 5, true
	default:
		return 0, false
	}
}

func normalizeRouteRefreshConfig(ctx context.Context, tx *sql.Tx) error {
	data, ok, err := loadSettingsKV(ctx, tx, "route_extra", "refresh_config")
	if err != nil || !ok {
		return err
	}
	var legacy legacyconfig.RefreshConfig
	if err := json.Unmarshal([]byte(data), &legacy); err != nil {
		return fmt.Errorf("decode legacy route refresh config: %w", err)
	}
	return saveCanonicalSettingsKV(ctx, tx, "route_extra", "refresh_config", canonicalRouteRefreshConfig{
		RefreshInterval: legacy.GetRefreshInterval(),
		LastRefreshTime: legacy.GetLastRefreshTime(),
		Error:           legacy.GetError(),
	})
}

func loadSettingsKV(ctx context.Context, tx *sql.Tx, section, key string) (string, bool, error) {
	var data string
	err := tx.QueryRowContext(ctx, `
		SELECT value_json FROM settings_kv WHERE section = ? AND key = ?
	`, section, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("query legacy %s.%s: %w", section, key, err)
	}
	return data, true, nil
}

func saveCanonicalSettingsKV(ctx context.Context, tx *sql.Tx, section, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE settings_kv SET value_json = ? WHERE section = ? AND key = ?
	`, string(data), section, key); err != nil {
		return fmt.Errorf("save canonical %s.%s: %w", section, key, err)
	}
	return nil
}
