package chore

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var _ DB = (*SqliteDB)(nil)

type SqliteDB struct {
	path        string
	mu          sync.Mutex
	store       *storagesqlite.Store
	initialized bool
}

func NewSqliteDB(path string) *SqliteDB { return &SqliteDB{path: path} }

func (c *SqliteDB) View(f ...func(*config.Setting) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ctx := context.Background()
	store, err := c.openLocked(ctx)
	if err != nil {
		return err
	}

	tx, err := store.DB().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin sqlite view transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	setting, err := c.loadSettingTx(ctx, tx)
	if err != nil {
		return err
	}

	for _, fn := range f {
		if err := fn(setting); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite view transaction failed: %w", err)
	}

	return nil
}

func (c *SqliteDB) Batch(f ...func(*config.Setting) error) error {
	if len(f) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ctx := context.Background()
	store, err := c.openLocked(ctx)
	if err != nil {
		return err
	}

	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite batch transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	setting, err := c.loadSettingTx(ctx, tx)
	if err != nil {
		return err
	}

	for _, fn := range f {
		if err := fn(setting); err != nil {
			return err
		}
	}

	if err := c.saveSettingTx(ctx, tx, setting); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite batch transaction failed: %w", err)
	}

	return nil
}

func (c *SqliteDB) Dir() string { return filepath.Dir(c.path) }

func (c *SqliteDB) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.store == nil {
		return nil
	}
	err := c.store.Close()
	c.store = nil
	c.initialized = false
	return err
}

func (c *SqliteDB) openLocked(ctx context.Context) (*storagesqlite.Store, error) {
	if c.store == nil {
		store, err := storagesqlite.Open(ctx, c.path)
		if err != nil {
			return nil, fmt.Errorf("open sqlite setting store failed: %w", err)
		}
		c.store = store
	}

	if !c.initialized {
		if err := c.ensureInitialized(ctx, c.store.DB()); err != nil {
			return nil, err
		}
		c.initialized = true
	}

	return c.store, nil
}

func (c *SqliteDB) ensureInitialized(ctx context.Context, db *sql.DB) error {
	if err := c.ensureConfigImported(ctx, db); err != nil {
		return err
	}

	if err := c.ensureAndroidPreferencesImported(ctx, db); err != nil {
		return err
	}

	return nil
}

func (c *SqliteDB) ensureConfigImported(ctx context.Context, db *sql.DB) error {
	done, err := loadMetadata(ctx, db, "legacy_config_import_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	if ok, err := hasConfigState(ctx, db); err != nil {
		return err
	} else if ok {
		return updateMetadata(ctx, db, map[string]string{
			"legacy_config_import_done":   "1",
			"legacy_config_import_source": "existing_sqlite",
		})
	}

	setting, source, err := c.loadLegacyConfig()
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite legacy config import transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := c.saveSettingTx(ctx, tx, setting); err != nil {
		return err
	}

	if err := updateMetadataTx(ctx, tx, map[string]string{
		"legacy_config_import_done":   "1",
		"legacy_config_import_source": source,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite legacy config import transaction failed: %w", err)
	}

	return nil
}

func (c *SqliteDB) ensureAndroidPreferencesImported(ctx context.Context, db *sql.DB) error {
	done, err := loadMetadata(ctx, db, "legacy_android_preferences_import_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	var existing int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM android_extra_preferences`).Scan(&existing); err != nil {
		return fmt.Errorf("count android_extra_preferences failed: %w", err)
	}
	if existing > 0 {
		return updateMetadata(ctx, db, map[string]string{
			"legacy_android_preferences_import_done":   "1",
			"legacy_android_preferences_import_source": "existing_sqlite",
		})
	}

	store, ok, err := loadLegacyAndroidMemoryStore(filepath.Join(c.Dir(), "yuhaiin_memory_store.json"))
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite android preferences import transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if ok {
		if err := saveAndroidPreferencesTx(ctx, tx, store); err != nil {
			return err
		}
	}

	source := "missing"
	if ok {
		source = "yuhaiin_memory_store.json"
	}

	if err := updateMetadataTx(ctx, tx, map[string]string{
		"legacy_android_preferences_import_done":   "1",
		"legacy_android_preferences_import_source": source,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite android preferences import transaction failed: %w", err)
	}

	return nil
}

func (c *SqliteDB) loadLegacyConfig() (*config.Setting, string, error) {
	dir := c.Dir()
	setting := config.DefaultSetting(dir)
	sources := []string{"defaults"}

	configPath := tools.PathGenerator.Config(dir)
	if fileExists(configPath) {
		setting = jsondb.Open(configPath, config.DefaultSetting(dir)).Data
		sources = append(sources, "config.json")
	}

	if ok, err := applyLegacyAndroidConfigStore(filepath.Join(dir, "yuhaiin_memory_config_store.json"), setting, dir); err != nil {
		return nil, "", err
	} else if ok {
		sources = append(sources, "yuhaiin_memory_config_store.json")
	}

	normalizeSetting(setting, dir)
	return setting, strings.Join(sources, ","), nil
}

func (c *SqliteDB) loadSettingTx(ctx context.Context, tx *sql.Tx) (*config.Setting, error) {
	setting := config.DefaultSetting(c.Dir())

	if err := loadSettingsKVTx(ctx, tx, setting); err != nil {
		return nil, err
	}
	if err := loadDNSTx(ctx, tx, setting); err != nil {
		return nil, err
	}
	if err := loadInboundTx(ctx, tx, setting); err != nil {
		return nil, err
	}
	if err := loadRouteTx(ctx, tx, setting); err != nil {
		return nil, err
	}
	if err := loadBackupTx(ctx, tx, setting); err != nil {
		return nil, err
	}

	normalizeSetting(setting, c.Dir())
	return setting, nil
}

func (c *SqliteDB) saveSettingTx(ctx context.Context, tx *sql.Tx, setting *config.Setting) error {
	normalizeSetting(setting, c.Dir())

	now := time.Now().Unix()

	if err := clearTables(ctx, tx,
		"settings_kv",
		"dns_settings",
		"dns_resolvers",
		"dns_hosts",
		"dns_fakedns_lists",
		"inbound_settings",
		"inbounds",
		"route_settings",
		"route_rules",
		"route_lists",
		"route_list_refresh",
		"backup_settings",
	); err != nil {
		return err
	}

	if err := saveSettingsKVTx(ctx, tx, setting, now); err != nil {
		return err
	}
	if err := saveDNSTx(ctx, tx, setting.GetDns(), now); err != nil {
		return err
	}
	if err := saveInboundTx(ctx, tx, setting.GetServer(), now); err != nil {
		return err
	}
	if err := saveRouteTx(ctx, tx, setting.GetBypass(), now); err != nil {
		return err
	}
	if err := saveBackupTx(ctx, tx, setting.GetBackup(), now); err != nil {
		return err
	}

	return nil
}

func loadSettingsKVTx(ctx context.Context, tx *sql.Tx, setting *config.Setting) error {
	rows, err := tx.QueryContext(ctx, `SELECT section, key, value_json FROM settings_kv`)
	if err != nil {
		return fmt.Errorf("query settings_kv failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var section, key, valueJSON string
		if err := rows.Scan(&section, &key, &valueJSON); err != nil {
			return fmt.Errorf("scan settings_kv failed: %w", err)
		}

		switch section {
		case "general":
			switch key {
			case "ipv6":
				if value, err := decodeJSONValue[bool](valueJSON); err == nil {
					setting.SetIpv6(value)
				} else {
					return fmt.Errorf("decode general.ipv6 failed: %w", err)
				}
			case "use_default_interface":
				if value, err := decodeJSONValue[bool](valueJSON); err == nil {
					setting.SetUseDefaultInterface(value)
				} else {
					return fmt.Errorf("decode general.use_default_interface failed: %w", err)
				}
			case "net_interface":
				if value, err := decodeJSONValue[string](valueJSON); err == nil {
					setting.SetNetInterface(value)
				} else {
					return fmt.Errorf("decode general.net_interface failed: %w", err)
				}
			}
		case "system_proxy":
			switch key {
			case "http":
				if value, err := decodeJSONValue[bool](valueJSON); err == nil {
					setting.GetSystemProxy().SetHttp(value)
				} else {
					return fmt.Errorf("decode system_proxy.http failed: %w", err)
				}
			case "socks5":
				if value, err := decodeJSONValue[bool](valueJSON); err == nil {
					setting.GetSystemProxy().SetSocks5(value)
				} else {
					return fmt.Errorf("decode system_proxy.socks5 failed: %w", err)
				}
			}
		case "logcat":
			switch key {
			case "level":
				if value, err := decodeJSONValue[int32](valueJSON); err == nil {
					setting.GetLogcat().SetLevel(config.LogLevel(value))
				} else {
					return fmt.Errorf("decode logcat.level failed: %w", err)
				}
			case "save":
				if value, err := decodeJSONValue[bool](valueJSON); err == nil {
					setting.GetLogcat().SetSave(value)
				} else {
					return fmt.Errorf("decode logcat.save failed: %w", err)
				}
			case "ignore_dns_error":
				if value, err := decodeJSONValue[bool](valueJSON); err == nil {
					setting.GetLogcat().SetIgnoreDnsError(value)
				} else {
					return fmt.Errorf("decode logcat.ignore_dns_error failed: %w", err)
				}
			case "ignore_timeout_error":
				if value, err := decodeJSONValue[bool](valueJSON); err == nil {
					setting.GetLogcat().SetIgnoreTimeoutError(value)
				} else {
					return fmt.Errorf("decode logcat.ignore_timeout_error failed: %w", err)
				}
			}
		case "advanced":
			switch key {
			case "udp_buffer_size":
				if value, err := decodeJSONValue[int32](valueJSON); err == nil {
					setting.GetAdvancedConfig().SetUdpBufferSize(value)
				} else {
					return fmt.Errorf("decode advanced.udp_buffer_size failed: %w", err)
				}
			case "relay_buffer_size":
				if value, err := decodeJSONValue[int32](valueJSON); err == nil {
					setting.GetAdvancedConfig().SetRelayBufferSize(value)
				} else {
					return fmt.Errorf("decode advanced.relay_buffer_size failed: %w", err)
				}
			case "udp_ringbuffer_size":
				if value, err := decodeJSONValue[int32](valueJSON); err == nil {
					setting.GetAdvancedConfig().SetUdpRingbufferSize(value)
				} else {
					return fmt.Errorf("decode advanced.udp_ringbuffer_size failed: %w", err)
				}
			case "happyeyeballs_semaphore":
				if value, err := decodeJSONValue[int32](valueJSON); err == nil {
					setting.GetAdvancedConfig().SetHappyeyeballsSemaphore(value)
				} else {
					return fmt.Errorf("decode advanced.happyeyeballs_semaphore failed: %w", err)
				}
			}
		case "setting":
			switch key {
			case "platform":
				platform := &config.Platform{}
				if err := decodeProtoJSON(valueJSON, platform); err != nil {
					return fmt.Errorf("decode setting.platform failed: %w", err)
				}
				setting.SetPlatform(platform)
			case "config_version":
				version := &config.ConfigVersion{}
				if err := decodeProtoJSON(valueJSON, version); err != nil {
					return fmt.Errorf("decode setting.config_version failed: %w", err)
				}
				setting.SetConfigVersion(version)
			}
		case "route_extra":
			switch key {
			case "maxminddb_geoip":
				geoip := &config.MaxminddbGeoip{}
				if err := decodeProtoJSON(valueJSON, geoip); err != nil {
					return fmt.Errorf("decode route_extra.maxminddb_geoip failed: %w", err)
				}
				setting.GetBypass().SetMaxminddbGeoip(geoip)
			case "refresh_config":
				refresh := &config.RefreshConfig{}
				if err := decodeProtoJSON(valueJSON, refresh); err != nil {
					return fmt.Errorf("decode route_extra.refresh_config failed: %w", err)
				}
				setting.GetBypass().SetRefreshConfig(refresh)
			}
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate settings_kv failed: %w", err)
	}

	return nil
}

func loadDNSTx(ctx context.Context, tx *sql.Tx, setting *config.Setting) error {
	var (
		server         string
		fakednsEnabled int
		fakednsIPv4    string
		fakednsIPv6    string
		hasDNSSettings bool
	)

	err := tx.QueryRowContext(ctx, `
		SELECT server, fakedns_enabled, fakedns_ipv4_range, fakedns_ipv6_range
		FROM dns_settings
		WHERE id = 1
	`).Scan(&server, &fakednsEnabled, &fakednsIPv4, &fakednsIPv6)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("query dns_settings failed: %w", err)
	default:
		hasDNSSettings = true
	}

	if !hasDNSSettings {
		return nil
	}

	dnsSetting := setting.GetDns()
	dnsSetting.SetServer(server)
	dnsSetting.SetFakedns(fakednsEnabled != 0)
	dnsSetting.SetFakednsIpRange(fakednsIPv4)
	dnsSetting.SetFakednsIpv6Range(fakednsIPv6)
	dnsSetting.SetResolver(map[string]*config.Dns{})
	dnsSetting.SetHosts(map[string]string{})
	dnsSetting.SetFakednsWhitelist(nil)
	dnsSetting.SetFakednsSkipCheckList(nil)

	resolverRows, err := tx.QueryContext(ctx, `
		SELECT name, data_json
		FROM dns_resolvers
		ORDER BY name
	`)
	if err != nil {
		return fmt.Errorf("query dns_resolvers failed: %w", err)
	}
	defer resolverRows.Close()

	for resolverRows.Next() {
		var name, dataJSON string
		if err := resolverRows.Scan(&name, &dataJSON); err != nil {
			return fmt.Errorf("scan dns_resolvers failed: %w", err)
		}

		d := &config.Dns{}
		if err := decodeProtoJSON(dataJSON, d); err != nil {
			return fmt.Errorf("decode dns resolver %q failed: %w", name, err)
		}

		dnsSetting.GetResolver()[name] = d
	}
	if err := resolverRows.Err(); err != nil {
		return fmt.Errorf("iterate dns_resolvers failed: %w", err)
	}

	hostRows, err := tx.QueryContext(ctx, `
		SELECT host, target
		FROM dns_hosts
		ORDER BY host
	`)
	if err != nil {
		return fmt.Errorf("query dns_hosts failed: %w", err)
	}
	defer hostRows.Close()

	for hostRows.Next() {
		var host, target string
		if err := hostRows.Scan(&host, &target); err != nil {
			return fmt.Errorf("scan dns_hosts failed: %w", err)
		}
		dnsSetting.GetHosts()[host] = target
	}
	if err := hostRows.Err(); err != nil {
		return fmt.Errorf("iterate dns_hosts failed: %w", err)
	}

	listRows, err := tx.QueryContext(ctx, `
		SELECT kind, value
		FROM dns_fakedns_lists
		ORDER BY rowid
	`)
	if err != nil {
		return fmt.Errorf("query dns_fakedns_lists failed: %w", err)
	}
	defer listRows.Close()

	for listRows.Next() {
		var kind, value string
		if err := listRows.Scan(&kind, &value); err != nil {
			return fmt.Errorf("scan dns_fakedns_lists failed: %w", err)
		}

		switch kind {
		case "whitelist":
			dnsSetting.SetFakednsWhitelist(append(dnsSetting.GetFakednsWhitelist(), value))
		case "skip_check":
			dnsSetting.SetFakednsSkipCheckList(append(dnsSetting.GetFakednsSkipCheckList(), value))
		}
	}
	if err := listRows.Err(); err != nil {
		return fmt.Errorf("iterate dns_fakedns_lists failed: %w", err)
	}

	return nil
}

func loadInboundTx(ctx context.Context, tx *sql.Tx, setting *config.Setting) error {
	var (
		hijackDNS      int
		hijackDNSFake  int
		sniffEnabled   int
		hasInboundData bool
	)

	err := tx.QueryRowContext(ctx, `
		SELECT hijack_dns, hijack_dns_fakeip, sniff_enabled
		FROM inbound_settings
		WHERE id = 1
	`).Scan(&hijackDNS, &hijackDNSFake, &sniffEnabled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("query inbound_settings failed: %w", err)
	default:
		hasInboundData = true
	}

	if !hasInboundData {
		return nil
	}

	server := setting.GetServer()
	server.SetHijackDns(hijackDNS != 0)
	server.SetHijackDnsFakeip(hijackDNSFake != 0)
	sniff := server.GetSniff()
	if sniff == nil {
		sniff = &config.Sniff{}
	}
	sniff.SetEnabled(sniffEnabled != 0)
	server.SetSniff(sniff)
	server.SetInbounds(map[string]*config.Inbound{})

	rows, err := tx.QueryContext(ctx, `
		SELECT name, data_json
		FROM inbounds
		ORDER BY name
	`)
	if err != nil {
		return fmt.Errorf("query inbounds failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			return fmt.Errorf("scan inbounds failed: %w", err)
		}

		inbound := &config.Inbound{}
		if err := decodeProtoJSON(dataJSON, inbound); err != nil {
			return fmt.Errorf("decode inbound %q failed: %w", name, err)
		}

		server.GetInbounds()[name] = inbound
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate inbounds failed: %w", err)
	}

	return nil
}

func loadRouteTx(ctx context.Context, tx *sql.Tx, setting *config.Setting) error {
	var (
		directResolver string
		proxyResolver  string
		resolveLocally int
		udpProxyFqdn   int
		hasRouteData   bool
	)

	err := tx.QueryRowContext(ctx, `
		SELECT direct_resolver, proxy_resolver, resolve_locally, udp_proxy_fqdn
		FROM route_settings
		WHERE id = 1
	`).Scan(&directResolver, &proxyResolver, &resolveLocally, &udpProxyFqdn)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("query route_settings failed: %w", err)
	default:
		hasRouteData = true
	}

	if !hasRouteData {
		return nil
	}

	bypass := setting.GetBypass()
	bypass.SetDirectResolver(directResolver)
	bypass.SetProxyResolver(proxyResolver)
	bypass.SetResolveLocally(resolveLocally != 0)
	bypass.SetUdpProxyFqdn(config.UdpProxyFqdnStrategy(udpProxyFqdn))
	bypass.SetRulesV2(nil)
	bypass.SetLists(map[string]*config.List{})

	ruleRows, err := tx.QueryContext(ctx, `
		SELECT data_json
		FROM route_rules
		ORDER BY priority ASC
	`)
	if err != nil {
		return fmt.Errorf("query route_rules failed: %w", err)
	}
	defer ruleRows.Close()

	for ruleRows.Next() {
		var dataJSON string
		if err := ruleRows.Scan(&dataJSON); err != nil {
			return fmt.Errorf("scan route_rules failed: %w", err)
		}

		rule := &config.Rulev2{}
		if err := decodeProtoJSON(dataJSON, rule); err != nil {
			return fmt.Errorf("decode route rule failed: %w", err)
		}

		bypass.SetRulesV2(append(bypass.GetRulesV2(), rule))
	}
	if err := ruleRows.Err(); err != nil {
		return fmt.Errorf("iterate route_rules failed: %w", err)
	}

	listRows, err := tx.QueryContext(ctx, `
		SELECT name, data_json
		FROM route_lists
		ORDER BY name
	`)
	if err != nil {
		return fmt.Errorf("query route_lists failed: %w", err)
	}
	defer listRows.Close()

	for listRows.Next() {
		var name, dataJSON string
		if err := listRows.Scan(&name, &dataJSON); err != nil {
			return fmt.Errorf("scan route_lists failed: %w", err)
		}

		list := &config.List{}
		if err := decodeProtoJSON(dataJSON, list); err != nil {
			return fmt.Errorf("decode route list %q failed: %w", name, err)
		}

		bypass.GetLists()[name] = list
	}
	if err := listRows.Err(); err != nil {
		return fmt.Errorf("iterate route_lists failed: %w", err)
	}

	return nil
}

func loadBackupTx(ctx context.Context, tx *sql.Tx, setting *config.Setting) error {
	var dataJSON string
	err := tx.QueryRowContext(ctx, `
		SELECT data_json
		FROM backup_settings
		WHERE id = 1
	`).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("query backup_settings failed: %w", err)
	}

	backup := &config.BackupOption{}
	if err := decodeProtoJSON(dataJSON, backup); err != nil {
		return fmt.Errorf("decode backup_settings failed: %w", err)
	}

	setting.SetBackup(backup)
	return nil
}

func saveSettingsKVTx(ctx context.Context, tx *sql.Tx, setting *config.Setting, now int64) error {
	if err := saveJSONKV(ctx, tx, "general", "ipv6", setting.GetIpv6(), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "general", "use_default_interface", setting.GetUseDefaultInterface(), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "general", "net_interface", setting.GetNetInterface(), now); err != nil {
		return err
	}

	if err := saveJSONKV(ctx, tx, "system_proxy", "http", setting.GetSystemProxy().GetHttp(), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "system_proxy", "socks5", setting.GetSystemProxy().GetSocks5(), now); err != nil {
		return err
	}

	if err := saveJSONKV(ctx, tx, "logcat", "level", int32(setting.GetLogcat().GetLevel()), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "logcat", "save", setting.GetLogcat().GetSave(), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "logcat", "ignore_dns_error", setting.GetLogcat().GetIgnoreDnsError(), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "logcat", "ignore_timeout_error", setting.GetLogcat().GetIgnoreTimeoutError(), now); err != nil {
		return err
	}

	if err := saveJSONKV(ctx, tx, "advanced", "udp_buffer_size", setting.GetAdvancedConfig().GetUdpBufferSize(), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "advanced", "relay_buffer_size", setting.GetAdvancedConfig().GetRelayBufferSize(), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "advanced", "udp_ringbuffer_size", setting.GetAdvancedConfig().GetUdpRingbufferSize(), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "advanced", "happyeyeballs_semaphore", setting.GetAdvancedConfig().GetHappyeyeballsSemaphore(), now); err != nil {
		return err
	}

	if err := saveProtoJSONKV(ctx, tx, "setting", "platform", nonNilPlatform(setting.GetPlatform()), now); err != nil {
		return err
	}
	if err := saveProtoJSONKV(ctx, tx, "setting", "config_version", nonNilConfigVersion(setting.GetConfigVersion()), now); err != nil {
		return err
	}
	if err := saveProtoJSONKV(ctx, tx, "route_extra", "maxminddb_geoip", nonNilMaxminddbGeoip(setting.GetBypass().GetMaxminddbGeoip()), now); err != nil {
		return err
	}
	if err := saveProtoJSONKV(ctx, tx, "route_extra", "refresh_config", nonNilRefreshConfig(setting.GetBypass().GetRefreshConfig()), now); err != nil {
		return err
	}

	return nil
}

func saveDNSTx(ctx context.Context, tx *sql.Tx, dnsSetting *config.DnsConfig, now int64) error {
	if dnsSetting == nil {
		dnsSetting = &config.DnsConfig{}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dns_settings(id, server, fakedns_enabled, fakedns_ipv4_range, fakedns_ipv6_range)
		VALUES (1, ?, ?, ?, ?)
	`, dnsSetting.GetServer(), boolToInt(dnsSetting.GetFakedns()), dnsSetting.GetFakednsIpRange(), dnsSetting.GetFakednsIpv6Range()); err != nil {
		return fmt.Errorf("insert dns_settings failed: %w", err)
	}

	resolverKeys := slices.Collect(maps.Keys(dnsSetting.GetResolver()))
	slices.Sort(resolverKeys)
	for _, name := range resolverKeys {
		resolver := dnsSetting.GetResolver()[name]
		dataJSON, err := encodeProtoJSON(resolver)
		if err != nil {
			return fmt.Errorf("encode dns resolver %q failed: %w", name, err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dns_resolvers(name, resolver_type, host, subnet, tls_servername, data_json)
			VALUES (?, ?, ?, ?, ?, ?)
		`, name, int(resolver.GetType()), resolver.GetHost(), resolver.GetSubnet(), resolver.GetTlsServername(), dataJSON); err != nil {
			return fmt.Errorf("insert dns resolver %q failed: %w", name, err)
		}
	}

	hostKeys := slices.Collect(maps.Keys(dnsSetting.GetHosts()))
	slices.Sort(hostKeys)
	for _, host := range hostKeys {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dns_hosts(host, target)
			VALUES (?, ?)
		`, host, dnsSetting.GetHosts()[host]); err != nil {
			return fmt.Errorf("insert dns host %q failed: %w", host, err)
		}
	}

	for _, value := range dnsSetting.GetFakednsWhitelist() {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dns_fakedns_lists(kind, value)
			VALUES ('whitelist', ?)
		`, value); err != nil {
			return fmt.Errorf("insert dns whitelist %q failed: %w", value, err)
		}
	}

	for _, value := range dnsSetting.GetFakednsSkipCheckList() {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dns_fakedns_lists(kind, value)
			VALUES ('skip_check', ?)
		`, value); err != nil {
			return fmt.Errorf("insert dns skip_check %q failed: %w", value, err)
		}
	}

	return nil
}

func saveInboundTx(ctx context.Context, tx *sql.Tx, inboundSetting *config.InboundConfig, now int64) error {
	if inboundSetting == nil {
		inboundSetting = &config.InboundConfig{}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO inbound_settings(id, hijack_dns, hijack_dns_fakeip, sniff_enabled)
		VALUES (1, ?, ?, ?)
	`, boolToInt(inboundSetting.GetHijackDns()), boolToInt(inboundSetting.GetHijackDnsFakeip()), boolToInt(inboundSetting.GetSniff().GetEnabled())); err != nil {
		return fmt.Errorf("insert inbound_settings failed: %w", err)
	}

	inboundNames := slices.Collect(maps.Keys(inboundSetting.GetInbounds()))
	slices.Sort(inboundNames)
	for _, name := range inboundNames {
		inbound := inboundSetting.GetInbounds()[name]
		dataJSON, err := encodeProtoJSON(inbound)
		if err != nil {
			return fmt.Errorf("encode inbound %q failed: %w", name, err)
		}

		listenHost := ""
		if tcpudp := inbound.GetTcpudp(); tcpudp != nil {
			if host, _, err := net.SplitHostPort(tcpudp.GetHost()); err == nil {
				listenHost = host
			} else {
				listenHost = tcpudp.GetHost()
			}
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO inbounds(name, enabled, inbound_type, listen_host, updated_at, data_json)
			VALUES (?, ?, ?, ?, ?, ?)
		`, name, boolToInt(inbound.GetEnabled()), inboundType(inbound), listenHost, now, dataJSON); err != nil {
			return fmt.Errorf("insert inbound %q failed: %w", name, err)
		}
	}

	return nil
}

func saveRouteTx(ctx context.Context, tx *sql.Tx, bypass *config.BypassConfig, now int64) error {
	if bypass == nil {
		bypass = &config.BypassConfig{}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO route_settings(id, direct_resolver, proxy_resolver, resolve_locally, udp_proxy_fqdn)
		VALUES (1, ?, ?, ?, ?)
	`, bypass.GetDirectResolver(), bypass.GetProxyResolver(), boolToInt(bypass.GetResolveLocally()), int(bypass.GetUdpProxyFqdn())); err != nil {
		return fmt.Errorf("insert route_settings failed: %w", err)
	}

	for priority, rule := range bypass.GetRulesV2() {
		dataJSON, err := encodeProtoJSON(rule)
		if err != nil {
			return fmt.Errorf("encode route rule %q failed: %w", rule.GetName(), err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO route_rules(name, priority, disabled, updated_at, data_json)
			VALUES (?, ?, ?, ?, ?)
		`, rule.GetName(), priority, boolToInt(rule.GetDisabled()), now, dataJSON); err != nil {
			return fmt.Errorf("insert route rule %q failed: %w", rule.GetName(), err)
		}
	}

	listKeys := slices.Collect(maps.Keys(bypass.GetLists()))
	slices.Sort(listKeys)
	for _, name := range listKeys {
		list := bypass.GetLists()[name]
		dataJSON, err := encodeProtoJSON(list)
		if err != nil {
			return fmt.Errorf("encode route list %q failed: %w", name, err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO route_lists(name, kind, updated_at, data_json)
			VALUES (?, ?, ?, ?)
		`, name, routeListKind(list), now, dataJSON); err != nil {
			return fmt.Errorf("insert route list %q failed: %w", name, err)
		}
	}

	return nil
}

func saveBackupTx(ctx context.Context, tx *sql.Tx, backup *config.BackupOption, now int64) error {
	if backup == nil {
		return nil
	}

	dataJSON, err := encodeProtoJSON(backup)
	if err != nil {
		return fmt.Errorf("encode backup_settings failed: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO backup_settings(id, updated_at, data_json)
		VALUES (1, ?, ?)
	`, now, dataJSON); err != nil {
		return fmt.Errorf("insert backup_settings failed: %w", err)
	}

	return nil
}

func clearTables(ctx context.Context, tx *sql.Tx, tables ...string) error {
	for _, table := range tables {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear table %s failed: %w", table, err)
		}
	}
	return nil
}

func saveJSONKV(ctx context.Context, tx *sql.Tx, section, key string, value any, now int64) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal settings_kv %s.%s failed: %w", section, key, err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO settings_kv(section, key, value_json, updated_at)
		VALUES (?, ?, ?, ?)
	`, section, key, string(data), now); err != nil {
		return fmt.Errorf("insert settings_kv %s.%s failed: %w", section, key, err)
	}

	return nil
}

func saveProtoJSONKV(ctx context.Context, tx *sql.Tx, section, key string, value proto.Message, now int64) error {
	data, err := encodeProtoJSON(value)
	if err != nil {
		return fmt.Errorf("marshal settings_kv %s.%s failed: %w", section, key, err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO settings_kv(section, key, value_json, updated_at)
		VALUES (?, ?, ?, ?)
	`, section, key, data, now); err != nil {
		return fmt.Errorf("insert settings_kv %s.%s failed: %w", section, key, err)
	}

	return nil
}

func hasConfigState(ctx context.Context, db *sql.DB) (bool, error) {
	for _, table := range []string{
		"settings_kv",
		"dns_settings",
		"dns_resolvers",
		"dns_hosts",
		"inbound_settings",
		"inbounds",
		"route_settings",
		"route_rules",
		"route_lists",
		"backup_settings",
	} {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			return false, fmt.Errorf("count %s failed: %w", table, err)
		}
		if count > 0 {
			return true, nil
		}
	}
	return false, nil
}

func loadMetadata(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) (string, error) {
	var value string
	err := queryer.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("load metadata %q failed: %w", key, err)
	default:
		return value, nil
	}
}

func updateMetadata(ctx context.Context, db *sql.DB, values map[string]string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin metadata transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := updateMetadataTx(ctx, tx, values); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit metadata transaction failed: %w", err)
	}
	return nil
}

func updateMetadataTx(ctx context.Context, tx *sql.Tx, values map[string]string) error {
	keys := slices.Collect(maps.Keys(values))
	slices.Sort(keys)

	for _, key := range keys {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO metadata(key, value)
			VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, values[key]); err != nil {
			return fmt.Errorf("update metadata %q failed: %w", key, err)
		}
	}
	return nil
}

func applyLegacyAndroidConfigStore(path string, setting *config.Setting, dir string) (bool, error) {
	store, ok, err := loadLegacyAndroidMemoryStore(path)
	if err != nil || !ok {
		return ok, err
	}

	imported := false
	defaultSetting := config.DefaultSetting(dir)

	if data := store.Bytes.Values["chore_db"]; len(data) > 0 {
		legacySetting := config.DefaultSetting(dir)
		if err := proto.Unmarshal(data, legacySetting); err != nil {
			return false, fmt.Errorf("unmarshal android chore_db failed: %w", err)
		}

		setting.SetIpv6(legacySetting.GetIpv6())
		setting.SetUseDefaultInterface(legacySetting.GetUseDefaultInterface())
		setting.SetNetInterface(legacySetting.GetNetInterface())
		setting.SetSystemProxy(proto.CloneOf(legacySetting.GetSystemProxy()))
		setting.SetLogcat(proto.CloneOf(legacySetting.GetLogcat()))
		setting.SetAdvancedConfig(proto.CloneOf(legacySetting.GetAdvancedConfig()))
		setting.SetPlatform(proto.CloneOf(legacySetting.GetPlatform()))
		setting.SetConfigVersion(proto.CloneOf(legacySetting.GetConfigVersion()))
		if legacySetting.GetBackup() != nil {
			setting.SetBackup(proto.CloneOf(legacySetting.GetBackup()))
		}
		imported = true
	}

	if data := store.Bytes.Values["resolver_db"]; len(data) > 0 {
		dnsSetting := proto.CloneOf(defaultSetting.GetDns())
		if err := proto.Unmarshal(data, dnsSetting); err != nil {
			return false, fmt.Errorf("unmarshal android resolver_db failed: %w", err)
		}
		setting.SetDns(dnsSetting)
		imported = true
	}

	if data := store.Bytes.Values["bypass_db"]; len(data) > 0 {
		bypass := proto.CloneOf(defaultSetting.GetBypass())
		if err := proto.Unmarshal(data, bypass); err != nil {
			return false, fmt.Errorf("unmarshal android bypass_db failed: %w", err)
		}
		setting.SetBypass(bypass)
		imported = true
	}

	if data := store.Bytes.Values["inbound_db"]; len(data) > 0 {
		inbound := proto.CloneOf(defaultSetting.GetServer())
		if err := proto.Unmarshal(data, inbound); err != nil {
			return false, fmt.Errorf("unmarshal android inbound_db failed: %w", err)
		}
		setting.SetServer(inbound)
		imported = true
	}

	if data := store.Bytes.Values["backup_db"]; len(data) > 0 {
		legacySetting := config.DefaultSetting(dir)
		if err := proto.Unmarshal(data, legacySetting); err != nil {
			return false, fmt.Errorf("unmarshal android backup_db failed: %w", err)
		}
		if legacySetting.GetBackup() != nil {
			setting.SetBackup(proto.CloneOf(legacySetting.GetBackup()))
		}
		imported = true
	}

	return imported, nil
}

type legacySingleStore[T any] struct {
	Values map[string]T `json:"values"`
}

type legacyAndroidMemoryStore struct {
	Strings legacySingleStore[string]  `json:"strings"`
	Ints    legacySingleStore[int32]   `json:"ints"`
	Bools   legacySingleStore[bool]    `json:"bools"`
	Longs   legacySingleStore[int64]   `json:"longs"`
	Floats  legacySingleStore[float32] `json:"floats"`
	Bytes   legacySingleStore[[]byte]  `json:"bytes"`
}

func loadLegacyAndroidMemoryStore(path string) (*legacyAndroidMemoryStore, bool, error) {
	if !fileExists(path) {
		return nil, false, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read legacy android store %q failed: %w", path, err)
	}

	store := &legacyAndroidMemoryStore{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, store); err != nil {
			return nil, false, fmt.Errorf("unmarshal legacy android store %q failed: %w", path, err)
		}
	}

	if store.Strings.Values == nil {
		store.Strings.Values = map[string]string{}
	}
	if store.Ints.Values == nil {
		store.Ints.Values = map[string]int32{}
	}
	if store.Bools.Values == nil {
		store.Bools.Values = map[string]bool{}
	}
	if store.Longs.Values == nil {
		store.Longs.Values = map[string]int64{}
	}
	if store.Floats.Values == nil {
		store.Floats.Values = map[string]float32{}
	}
	if store.Bytes.Values == nil {
		store.Bytes.Values = map[string][]byte{}
	}

	return store, true, nil
}

func saveAndroidPreferencesTx(ctx context.Context, tx *sql.Tx, store *legacyAndroidMemoryStore) error {
	now := time.Now().Unix()

	stringKeys := slices.Collect(maps.Keys(store.Strings.Values))
	slices.Sort(stringKeys)
	for _, key := range stringKeys {
		if err := saveJSONPreference(ctx, tx, key, store.Strings.Values[key], now); err != nil {
			return err
		}
	}

	intKeys := slices.Collect(maps.Keys(store.Ints.Values))
	slices.Sort(intKeys)
	for _, key := range intKeys {
		if err := saveJSONPreference(ctx, tx, key, store.Ints.Values[key], now); err != nil {
			return err
		}
	}

	boolKeys := slices.Collect(maps.Keys(store.Bools.Values))
	slices.Sort(boolKeys)
	for _, key := range boolKeys {
		if err := saveJSONPreference(ctx, tx, key, store.Bools.Values[key], now); err != nil {
			return err
		}
	}

	longKeys := slices.Collect(maps.Keys(store.Longs.Values))
	slices.Sort(longKeys)
	for _, key := range longKeys {
		if err := saveJSONPreference(ctx, tx, key, store.Longs.Values[key], now); err != nil {
			return err
		}
	}

	floatKeys := slices.Collect(maps.Keys(store.Floats.Values))
	slices.Sort(floatKeys)
	for _, key := range floatKeys {
		if err := saveJSONPreference(ctx, tx, key, store.Floats.Values[key], now); err != nil {
			return err
		}
	}

	byteKeys := slices.Collect(maps.Keys(store.Bytes.Values))
	slices.Sort(byteKeys)
	for _, key := range byteKeys {
		if err := saveJSONPreference(ctx, tx, key, store.Bytes.Values[key], now); err != nil {
			return err
		}
	}

	return nil
}

func saveJSONPreference(ctx context.Context, tx *sql.Tx, key string, value any, now int64) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal android preference %q failed: %w", key, err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO android_extra_preferences(key, value_json, updated_at)
		VALUES (?, ?, ?)
	`, key, string(data), now); err != nil {
		return fmt.Errorf("insert android preference %q failed: %w", key, err)
	}

	return nil
}

func encodeProtoJSON(msg proto.Message) (string, error) {
	data, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeProtoJSON(data string, msg proto.Message) error {
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal([]byte(data), msg)
}

func decodeJSONValue[T any](data string) (T, error) {
	var value T
	err := json.Unmarshal([]byte(data), &value)
	return value, err
}

func normalizeSetting(setting *config.Setting, dir string) {
	jsondb.MergeDefault(setting.ProtoReflect(), config.DefaultSetting(dir).ProtoReflect())
}

func nonNilPlatform(platform *config.Platform) *config.Platform {
	if platform != nil {
		return platform
	}
	return &config.Platform{}
}

func nonNilConfigVersion(version *config.ConfigVersion) *config.ConfigVersion {
	if version != nil {
		return version
	}
	return &config.ConfigVersion{}
}

func nonNilMaxminddbGeoip(geoip *config.MaxminddbGeoip) *config.MaxminddbGeoip {
	if geoip != nil {
		return geoip
	}
	return &config.MaxminddbGeoip{}
}

func nonNilRefreshConfig(refresh *config.RefreshConfig) *config.RefreshConfig {
	if refresh != nil {
		return refresh
	}
	return &config.RefreshConfig{}
}

func routeListKind(list *config.List) string {
	switch list.WhichList() {
	case config.List_Local_case:
		return "local"
	case config.List_Remote_case:
		return "remote"
	default:
		return "unknown"
	}
}

func inboundType(inbound *config.Inbound) string {
	switch inbound.WhichProtocol() {
	case config.Inbound_Http_case:
		return "http"
	case config.Inbound_Socks5_case:
		return "socks5"
	case config.Inbound_Yuubinsya_case:
		return "yuubinsya"
	case config.Inbound_Mix_case:
		return "mixed"
	case config.Inbound_Socks4A_case:
		return "socks4a"
	case config.Inbound_Tproxy_case:
		return "tproxy"
	case config.Inbound_Redir_case:
		return "redir"
	case config.Inbound_Tun_case:
		return "tun"
	case config.Inbound_ReverseHttp_case:
		return "reverse_http"
	case config.Inbound_ReverseTcp_case:
		return "reverse_tcp"
	case config.Inbound_None_case:
		return "none"
	}

	switch inbound.WhichNetwork() {
	case config.Inbound_Tcpudp_case:
		return "tcpudp"
	case config.Inbound_Quic_case:
		return "quic"
	case config.Inbound_Empty_case:
		return "empty"
	default:
		return "unknown"
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
