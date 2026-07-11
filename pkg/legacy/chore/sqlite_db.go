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

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/encoding/protowire"
)

var _ DB = (*SqliteDB)(nil)

const legacyAndroidProtobufRepairDoneKey = "legacy_android_protobuf_config_repair_done"

type SqliteDB struct {
	path        string
	mu          sync.Mutex
	store       *storagesqlite.Store
	initialized bool
}

type PlainMigrationWarning struct {
	Entity  string
	Message string
}

type PlainMigrationHooks struct {
	MigrateLegacyInbounds      func(context.Context, *sql.DB, int64) ([]PlainMigrationWarning, error)
	ImportLegacyNodes          func(context.Context, *sql.DB, string, int64) error
	MigrateLegacyNodes         func(context.Context, *sql.DB, int64) error
	MigrateLegacySubscriptions func(context.Context, *sql.DB, int64) error
	MigrateLegacyResolvers     func(context.Context, *sql.DB, int64) error
	MigrateLegacyRouteRules    func(context.Context, *sql.DB, int64) error
	MigrateLegacyRouteLists    func(context.Context, *sql.DB, int64) error
	MigrateLegacyRouteTags     func(context.Context, *sql.DB, int64) error
	ConvertLegacyInbound       func(string, *config.Inbound) (contractinbound.Inbound, []PlainMigrationWarning, error)
}

var plainMigrationHooks PlainMigrationHooks

func RegisterPlainMigrationHooks(hooks PlainMigrationHooks) {
	plainMigrationHooks = hooks
}

func NewSqliteDB(path string) *SqliteDB { return &SqliteDB{path: path} }

func NewExplicitMigrationSqliteDB(path string) *SqliteDB {
	return &SqliteDB{path: path}
}

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

func (c *SqliteDB) SQLDB(ctx context.Context) (*sql.DB, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	store, err := c.openLocked(ctx)
	if err != nil {
		return nil, err
	}
	return store.DB(), nil
}

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
	store, err := c.openSchemaLocked(ctx)
	if err != nil {
		return nil, err
	}

	if c.initialized {
		return store, nil
	}

	done, err := loadMetadata(ctx, store.DB(), "plain_model_migration_done")
	if err != nil {
		return nil, err
	}
	if done != "1" {
		return nil, errors.New("plain model migration has not run; call Migrate during app startup")
	}
	c.initialized = true
	return store, nil
}

func (c *SqliteDB) openSchemaLocked(ctx context.Context) (*storagesqlite.Store, error) {
	if c.store == nil {
		store, err := storagesqlite.Open(ctx, c.path)
		if err != nil {
			return nil, fmt.Errorf("open sqlite setting store failed: %w", err)
		}
		c.store = store
	}
	return c.store, nil
}

func (c *SqliteDB) Migrate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	store, err := c.openSchemaLocked(ctx)
	if err != nil {
		return err
	}
	if err := c.ensureInitialized(ctx, store.DB()); err != nil {
		return err
	}
	c.initialized = true
	return nil
}

func (c *SqliteDB) ensureInitialized(ctx context.Context, db *sql.DB) error {
	if err := c.ensureConfigImported(ctx, db); err != nil {
		return err
	}

	if err := c.ensureInboundSettingsInitialized(ctx, db); err != nil {
		return err
	}

	if err := c.ensurePlainInboundMigrated(ctx, db); err != nil {
		return err
	}

	if err := c.ensureLegacyNodesImported(ctx, db); err != nil {
		return err
	}

	if err := c.ensurePlainNodesMigrated(ctx, db); err != nil {
		return err
	}
	if err := c.ensurePlainSubscriptionsMigrated(ctx, db); err != nil {
		return err
	}

	if err := c.ensurePlainResolversMigrated(ctx, db); err != nil {
		return err
	}

	if err := c.ensurePlainRouteRulesMigrated(ctx, db); err != nil {
		return err
	}

	if err := c.ensurePlainRouteListsMigrated(ctx, db); err != nil {
		return err
	}

	if err := c.ensurePlainRouteTagsMigrated(ctx, db); err != nil {
		return err
	}

	if err := c.ensureAndroidPreferencesImported(ctx, db); err != nil {
		return err
	}

	return nil
}

func (c *SqliteDB) ensureInboundSettingsInitialized(ctx context.Context, db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM inbound_settings WHERE id = 1`).Scan(&count); err != nil {
		return fmt.Errorf("count inbound_settings failed: %w", err)
	}
	if count > 0 {
		return nil
	}

	server := config.DefaultSetting(c.Dir()).GetServer()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO inbound_settings(id, hijack_dns, hijack_dns_fakeip, sniff_enabled)
		VALUES (1, ?, ?, ?)
	`, boolToInt(server.GetHijackDns()), boolToInt(server.GetHijackDnsFakeip()), boolToInt(server.GetSniff().GetEnabled())); err != nil {
		return fmt.Errorf("insert default inbound_settings failed: %w", err)
	}
	return nil
}

func (c *SqliteDB) ensurePlainInboundMigrated(ctx context.Context, db *sql.DB) error {
	done, err := loadMetadata(ctx, db, "plain_inbounds_migration_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	if plainMigrationHooks.MigrateLegacyInbounds == nil {
		return errors.New("plain inbound migration hook is not registered")
	}
	warnings, err := plainMigrationHooks.MigrateLegacyInbounds(ctx, db, 0)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		fmt.Printf("plain inbound migration warning: %s: %s\n", warning.Entity, warning.Message)
	}
	return nil
}

func (c *SqliteDB) ensurePlainNodesMigrated(ctx context.Context, db *sql.DB) error {
	if plainMigrationHooks.MigrateLegacyNodes == nil {
		return errors.New("plain node migration hook is not registered")
	}
	return plainMigrationHooks.MigrateLegacyNodes(ctx, db, 0)
}

func (c *SqliteDB) ensurePlainSubscriptionsMigrated(ctx context.Context, db *sql.DB) error {
	if plainMigrationHooks.MigrateLegacySubscriptions == nil {
		return errors.New("plain subscription migration hook is not registered")
	}
	return plainMigrationHooks.MigrateLegacySubscriptions(ctx, db, 0)
}

func (c *SqliteDB) ensureLegacyNodesImported(ctx context.Context, db *sql.DB) error {
	if plainMigrationHooks.ImportLegacyNodes == nil {
		return errors.New("legacy node import hook is not registered")
	}
	return plainMigrationHooks.ImportLegacyNodes(ctx, db, c.Dir(), 0)
}

func (c *SqliteDB) ensurePlainResolversMigrated(ctx context.Context, db *sql.DB) error {
	if plainMigrationHooks.MigrateLegacyResolvers == nil {
		return errors.New("plain resolver migration hook is not registered")
	}
	return plainMigrationHooks.MigrateLegacyResolvers(ctx, db, 0)
}

func (c *SqliteDB) ensurePlainRouteRulesMigrated(ctx context.Context, db *sql.DB) error {
	if plainMigrationHooks.MigrateLegacyRouteRules == nil {
		return errors.New("plain route rule migration hook is not registered")
	}
	return plainMigrationHooks.MigrateLegacyRouteRules(ctx, db, 0)
}

func (c *SqliteDB) ensurePlainRouteListsMigrated(ctx context.Context, db *sql.DB) error {
	if plainMigrationHooks.MigrateLegacyRouteLists == nil {
		return errors.New("plain route list migration hook is not registered")
	}
	return plainMigrationHooks.MigrateLegacyRouteLists(ctx, db, 0)
}

func (c *SqliteDB) ensurePlainRouteTagsMigrated(ctx context.Context, db *sql.DB) error {
	if plainMigrationHooks.MigrateLegacyRouteTags == nil {
		return errors.New("plain route tag migration hook is not registered")
	}
	return plainMigrationHooks.MigrateLegacyRouteTags(ctx, db, 0)
}

func (c *SqliteDB) ensureConfigImported(ctx context.Context, db *sql.DB) error {
	done, err := loadMetadata(ctx, db, "legacy_config_import_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return c.repairLegacyAndroidProtobufConfig(ctx, db)
	}

	if ok, err := hasConfigState(ctx, db); err != nil {
		return err
	} else if ok {
		if err := updateMetadata(ctx, db, map[string]string{
			"legacy_config_import_done":   "1",
			"legacy_config_import_source": "existing_sqlite",
		}); err != nil {
			return err
		}
		return c.repairLegacyAndroidProtobufConfig(ctx, db)
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
		"legacy_config_import_done":        "1",
		"legacy_config_import_source":      source,
		legacyAndroidProtobufRepairDoneKey: "1",
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite legacy config import transaction failed: %w", err)
	}

	return nil
}

func (c *SqliteDB) repairLegacyAndroidProtobufConfig(ctx context.Context, db *sql.DB) error {
	done, err := loadMetadata(ctx, db, legacyAndroidProtobufRepairDoneKey)
	if err != nil || done == "1" {
		return err
	}
	path := filepath.Join(c.Dir(), "yuhaiin_memory_config_store.json")
	if !fileExists(path) {
		return updateMetadata(ctx, db, map[string]string{legacyAndroidProtobufRepairDoneKey: "1"})
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin Android protobuf config repair: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	setting, err := c.loadSettingTx(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := applyLegacyAndroidConfigStore(path, setting, c.Dir()); err != nil {
		return err
	}
	if err := c.saveSettingTx(ctx, tx, setting); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM metadata WHERE key IN (
		'plain_inbounds_migration_done', 'plain_resolvers_migration_done',
		'plain_route_rules_migration_done', 'plain_route_lists_migration_done',
		'plain_route_tags_migration_done'
	)`); err != nil {
		return fmt.Errorf("reset plain config migration markers: %w", err)
	}
	if err := updateMetadataTx(ctx, tx, map[string]string{legacyAndroidProtobufRepairDoneKey: "1"}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Android protobuf config repair: %w", err)
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

	configPath := paths.PathGenerator.Config(dir)
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
				if err := decodeJSONText(valueJSON, platform); err != nil {
					return fmt.Errorf("decode setting.platform failed: %w", err)
				}
				setting.SetPlatform(platform)
			case "config_version":
				version := &config.ConfigVersion{}
				if err := decodeJSONText(valueJSON, version); err != nil {
					return fmt.Errorf("decode setting.config_version failed: %w", err)
				}
				setting.SetConfigVersion(version)
			}
		case "route_extra":
			switch key {
			case "maxminddb_geoip":
				geoip := &config.MaxminddbGeoip{}
				if err := decodeJSONText(valueJSON, geoip); err != nil {
					return fmt.Errorf("decode route_extra.maxminddb_geoip failed: %w", err)
				}
				setting.GetBypass().SetMaxminddbGeoip(geoip)
			case "refresh_config":
				refresh := &config.RefreshConfig{}
				if err := decodeJSONText(valueJSON, refresh); err != nil {
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
		if err := decodeJSONText(dataJSON, d); err != nil {
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
		SELECT name, inbound_type, data_json
		FROM inbounds
		ORDER BY name
	`)
	if err != nil {
		return fmt.Errorf("query inbounds failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name, inboundTypeValue, dataJSON string
		if err := rows.Scan(&name, &inboundTypeValue, &dataJSON); err != nil {
			return fmt.Errorf("scan inbounds failed: %w", err)
		}

		inbound := &config.Inbound{}
		if err := decodeJSONText(dataJSON, inbound); err != nil {
			return fmt.Errorf("decode inbound %q failed: %w", name, err)
		}
		applyInboundTypeFallback(inbound, inboundTypeValue)
		inbound.SetName(name)

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
		if err := decodeJSONText(dataJSON, rule); err != nil {
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
		if err := decodeJSONText(dataJSON, list); err != nil {
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
	if err := decodeJSONText(dataJSON, backup); err != nil {
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

	if err := saveJSONKV(ctx, tx, "setting", "platform", nonNilPlatform(setting.GetPlatform()), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "setting", "config_version", nonNilConfigVersion(setting.GetConfigVersion()), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "route_extra", "maxminddb_geoip", nonNilMaxminddbGeoip(setting.GetBypass().GetMaxminddbGeoip()), now); err != nil {
		return err
	}
	if err := saveJSONKV(ctx, tx, "route_extra", "refresh_config", nonNilRefreshConfig(setting.GetBypass().GetRefreshConfig()), now); err != nil {
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
		dataJSON, err := encodeJSONText(resolver)
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
			INSERT OR IGNORE INTO dns_fakedns_lists(kind, value)
			VALUES ('whitelist', ?)
		`, value); err != nil {
			return fmt.Errorf("insert dns whitelist %q failed: %w", value, err)
		}
	}

	for _, value := range dnsSetting.GetFakednsSkipCheckList() {
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO dns_fakedns_lists(kind, value)
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
		applyInboundTypeFallback(inbound, name)
		dataJSON, err := encodeJSONText(inbound)
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

		if plainMigrationHooks.ConvertLegacyInbound == nil {
			return errors.New("plain inbound conversion hook is not registered")
		}
		contractInbound, warnings, err := plainMigrationHooks.ConvertLegacyInbound(name, inbound)
		if err != nil {
			return fmt.Errorf("convert inbound %q to plain contract failed: %w", name, err)
		}
		for _, warning := range warnings {
			fmt.Printf("plain inbound sync warning: %s: %s\n", warning.Entity, warning.Message)
		}
		if err := plainstore.SaveInboundContract(ctx, tx, contractInbound, now); err != nil {
			return fmt.Errorf("save plain inbound %q failed: %w", name, err)
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
		dataJSON, err := encodeJSONText(rule)
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
		dataJSON, err := encodeJSONText(list)
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

	dataJSON, err := encodeJSONText(backup)
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
		if err := json.Unmarshal(data, legacySetting); err == nil {
			setting.SetIpv6(legacySetting.GetIpv6())
			setting.SetUseDefaultInterface(legacySetting.GetUseDefaultInterface())
			setting.SetNetInterface(legacySetting.GetNetInterface())
			setting.SetSystemProxy(legacySetting.GetSystemProxy())
			setting.SetLogcat(legacySetting.GetLogcat())
			setting.SetAdvancedConfig(legacySetting.GetAdvancedConfig())
			setting.SetPlatform(legacySetting.GetPlatform())
			setting.SetConfigVersion(legacySetting.GetConfigVersion())
			if legacySetting.GetBackup() != nil {
				setting.SetBackup(legacySetting.GetBackup())
			}
		}
		// The legacy Android client ignored an unreadable configuration blob and
		// used its defaults. Do the same here; the original file is left intact.
		imported = true
	}

	if data := store.Bytes.Values["resolver_db"]; len(data) > 0 {
		dnsSetting := defaultSetting.GetDns()
		if err := json.Unmarshal(data, dnsSetting); err == nil || unmarshalLegacyAndroidResolverProto(data, dnsSetting) == nil {
			setting.SetDns(dnsSetting)
		}
		imported = true
	}

	if data := store.Bytes.Values["bypass_db"]; len(data) > 0 {
		bypass := defaultSetting.GetBypass()
		if err := json.Unmarshal(data, bypass); err == nil || unmarshalLegacyAndroidBypassProto(data, bypass) == nil {
			setting.SetBypass(bypass)
		}
		imported = true
	}

	if data := store.Bytes.Values["inbound_db"]; len(data) > 0 {
		inbound := defaultSetting.GetServer()
		if jsonErr := json.Unmarshal(data, inbound); jsonErr != nil {
			// Android releases before the JSON settings store wrote this value as a
			// protobuf message. Try that representation before treating the legacy
			// value as corrupt. Inbound listeners themselves were runtime-generated
			// on Android, so only the persisted runtime settings are recovered.
			if protoErr := unmarshalLegacyAndroidInboundProto(data, inbound); protoErr != nil {
				// Like the original Android store, retain defaults when neither
				// historic encoding can be read.
			} else {
				setting.SetServer(inbound)
			}
		} else {
			setting.SetServer(inbound)
		}
		imported = true
	}

	if data := store.Bytes.Values["backup_db"]; len(data) > 0 {
		legacySetting := config.DefaultSetting(dir)
		if err := json.Unmarshal(data, legacySetting); err != nil {
			// Older Android versions ignored an unreadable protobuf backup blob and
			// continued with the default backup settings. Preserve that behavior so
			// a stale or corrupt optional backup configuration cannot prevent VPN
			// startup after migration.
			imported = true
		} else if legacySetting.GetBackup() != nil {
			setting.SetBackup(legacySetting.GetBackup())
			imported = true
		}
	}

	return imported, nil
}

// unmarshalLegacyAndroidResolverProto decodes the protobuf representation used
// by Android's former resolver_db. Its fields intentionally mirror the legacy
// DnsConfig schema, so resolver names, hosts, fake-DNS ranges and strategies
// survive the SQLite migration.
func unmarshalLegacyAndroidResolverProto(data []byte, out *config.DnsConfig) error {
	if out == nil {
		return errors.New("dns config is nil")
	}
	out.SetResolver(map[string]*config.Dns{})
	out.SetHosts(map[string]string{})
	out.SetFakednsWhitelist(nil)
	out.SetFakednsSkipCheckList(nil)
	for len(data) > 0 {
		n, typ, size := protowire.ConsumeTag(data)
		if size < 0 {
			return protowire.ParseError(size)
		}
		data = data[size:]
		if n == 4 || n == 6 || n == 13 || n == 9 || n == 14 || n == 8 || n == 10 {
			if typ != protowire.BytesType {
				return fmt.Errorf("dns field %d has wire type %d", n, typ)
			}
			v, size := protowire.ConsumeBytes(data)
			if size < 0 {
				return protowire.ParseError(size)
			}
			data = data[size:]
			switch n {
			case 4:
				out.SetServer(string(v))
			case 6:
				out.SetFakednsIpRange(string(v))
			case 13:
				out.SetFakednsIpv6Range(string(v))
			case 9:
				out.SetFakednsWhitelist(append(out.GetFakednsWhitelist(), string(v)))
			case 14:
				out.SetFakednsSkipCheckList(append(out.GetFakednsSkipCheckList(), string(v)))
			case 8:
				k, val, err := legacyProtoStringMap(v)
				if err != nil {
					return err
				}
				out.GetHosts()[k] = val
			case 10:
				k, msg, err := legacyProtoMessageMap(v)
				if err != nil {
					return err
				}
				dns, err := legacyProtoDNS(msg)
				if err != nil {
					return err
				}
				out.GetResolver()[k] = dns
			}
			continue
		}
		if n == 5 {
			if typ != protowire.VarintType {
				return fmt.Errorf("fakedns has wire type %d", typ)
			}
			v, size := protowire.ConsumeVarint(data)
			if size < 0 {
				return protowire.ParseError(size)
			}
			out.SetFakedns(v != 0)
			data = data[size:]
			continue
		}
		size = protowire.ConsumeFieldValue(n, typ, data)
		if size < 0 {
			return protowire.ParseError(size)
		}
		data = data[size:]
	}
	return nil
}

func legacyProtoDNS(data []byte) (*config.Dns, error) {
	out := &config.Dns{}
	for len(data) > 0 {
		n, typ, size := protowire.ConsumeTag(data)
		if size < 0 {
			return nil, protowire.ParseError(size)
		}
		data = data[size:]
		switch n {
		case 1, 2, 4:
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("dns resolver field %d has wire type %d", n, typ)
			}
			v, s := protowire.ConsumeBytes(data)
			if s < 0 {
				return nil, protowire.ParseError(s)
			}
			switch n {
			case 1:
				out.SetHost(string(v))
			case 2:
				out.SetTlsServername(string(v))
			default:
				out.SetSubnet(string(v))
			}
			data = data[s:]
		case 5:
			if typ != protowire.VarintType {
				return nil, fmt.Errorf("dns resolver type has wire type %d", typ)
			}
			v, s := protowire.ConsumeVarint(data)
			if s < 0 {
				return nil, protowire.ParseError(s)
			}
			out.SetType(config.Type(v))
			data = data[s:]
		default:
			size = protowire.ConsumeFieldValue(n, typ, data)
			if size < 0 {
				return nil, protowire.ParseError(size)
			}
			data = data[size:]
		}
	}
	return out, nil
}

func legacyProtoStringMap(data []byte) (string, string, error) {
	k, v := "", ""
	for len(data) > 0 {
		n, typ, s := protowire.ConsumeTag(data)
		if s < 0 {
			return "", "", protowire.ParseError(s)
		}
		data = data[s:]
		if n == 1 || n == 2 {
			if typ != protowire.BytesType {
				return "", "", fmt.Errorf("map field %d has wire type %d", n, typ)
			}
			b, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return "", "", protowire.ParseError(x)
			}
			if n == 1 {
				k = string(b)
			} else {
				v = string(b)
			}
			data = data[x:]
		} else {
			s = protowire.ConsumeFieldValue(n, typ, data)
			if s < 0 {
				return "", "", protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return k, v, nil
}
func legacyProtoMessageMap(data []byte) (string, []byte, error) {
	k, v := "", []byte(nil)
	for len(data) > 0 {
		n, typ, s := protowire.ConsumeTag(data)
		if s < 0 {
			return "", nil, protowire.ParseError(s)
		}
		data = data[s:]
		if n == 1 || n == 2 {
			if typ != protowire.BytesType {
				return "", nil, fmt.Errorf("map field %d has wire type %d", n, typ)
			}
			b, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return "", nil, protowire.ParseError(x)
			}
			if n == 1 {
				k = string(b)
			} else {
				v = b
			}
			data = data[x:]
		} else {
			s = protowire.ConsumeFieldValue(n, typ, data)
			if s < 0 {
				return "", nil, protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return k, v, nil
}

// The route settings are top-level scalar protobuf fields. Rules and lists are
// migrated separately from their legacy tables when available.
func unmarshalLegacyAndroidBypassProto(data []byte, out *config.BypassConfig) error {
	if out == nil {
		return errors.New("bypass config is nil")
	}
	out.SetRulesV2(nil)
	out.SetLists(map[string]*config.List{})
	for len(data) > 0 {
		n, typ, s := protowire.ConsumeTag(data)
		if s < 0 {
			return protowire.ParseError(s)
		}
		data = data[s:]
		switch n {
		case 6, 9:
			if typ != protowire.VarintType {
				return fmt.Errorf("bypass field %d has wire type %d", n, typ)
			}
			v, x := protowire.ConsumeVarint(data)
			if x < 0 {
				return protowire.ParseError(x)
			}
			if n == 6 {
				out.SetUdpProxyFqdn(config.UdpProxyFqdnStrategy(v))
			} else {
				out.SetResolveLocally(v != 0)
			}
			data = data[x:]
		case 10, 11:
			if typ != protowire.BytesType {
				return fmt.Errorf("bypass field %d has wire type %d", n, typ)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return protowire.ParseError(x)
			}
			if n == 10 {
				out.SetDirectResolver(string(v))
			} else {
				out.SetProxyResolver(string(v))
			}
			data = data[x:]
		case 12:
			if typ != protowire.BytesType {
				return fmt.Errorf("bypass rules_v2 has wire type %d", typ)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return protowire.ParseError(x)
			}
			rule, err := legacyProtoRuleV2(v)
			if err != nil {
				return err
			}
			out.SetRulesV2(append(out.GetRulesV2(), rule))
			data = data[x:]
		case 13:
			if typ != protowire.BytesType {
				return fmt.Errorf("bypass lists has wire type %d", typ)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return protowire.ParseError(x)
			}
			name, message, err := legacyProtoMessageMap(v)
			if err != nil {
				return err
			}
			list, err := legacyProtoList(message)
			if err != nil {
				return err
			}
			if out.GetLists() == nil {
				out.SetLists(map[string]*config.List{})
			}
			if list.GetName() == "" {
				list.SetName(name)
			}
			out.GetLists()[name] = list
			data = data[x:]
		default:
			s = protowire.ConsumeFieldValue(n, typ, data)
			if s < 0 {
				return protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return nil
}

func legacyProtoRuleV2(data []byte) (*config.Rulev2, error) {
	out := &config.Rulev2{}
	for len(data) > 0 {
		n, typ, s := protowire.ConsumeTag(data)
		if s < 0 {
			return nil, protowire.ParseError(s)
		}
		data = data[s:]
		switch n {
		case 1, 3, 6:
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("rule field %d has wire type %d", n, typ)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return nil, protowire.ParseError(x)
			}
			switch n {
			case 1:
				out.SetName(string(v))
			case 3:
				out.SetTag(string(v))
			default:
				out.SetResolver(string(v))
			}
			data = data[x:]
		case 2, 4, 5, 8:
			if typ != protowire.VarintType {
				return nil, fmt.Errorf("rule field %d has wire type %d", n, typ)
			}
			v, x := protowire.ConsumeVarint(data)
			if x < 0 {
				return nil, protowire.ParseError(x)
			}
			switch n {
			case 2:
				out.SetMode(config.Mode(v))
			case 4:
				out.SetResolveStrategy(config.ResolveStrategy(v))
			case 5:
				out.SetUdpProxyFqdnStrategy(config.UdpProxyFqdnStrategy(v))
			case 8:
				out.SetDisabled(v != 0)
			}
			data = data[x:]
		case 7:
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("rule groups has wire type %d", typ)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return nil, protowire.ParseError(x)
			}
			group, err := legacyProtoOr(v)
			if err != nil {
				return nil, err
			}
			out.SetRules(append(out.GetRules(), group))
			data = data[x:]
		default:
			s = protowire.ConsumeFieldValue(n, typ, data)
			if s < 0 {
				return nil, protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return out, nil
}

func legacyProtoOr(data []byte) (*config.Or, error) {
	out := &config.Or{}
	for len(data) > 0 {
		n, typ, s := protowire.ConsumeTag(data)
		if s < 0 {
			return nil, protowire.ParseError(s)
		}
		data = data[s:]
		if n == 1 {
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("or rule has wire type %d", typ)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return nil, protowire.ParseError(x)
			}
			rule, err := legacyProtoRule(v)
			if err != nil {
				return nil, err
			}
			out.SetRules(append(out.GetRules(), rule))
			data = data[x:]
		} else {
			s = protowire.ConsumeFieldValue(n, typ, data)
			if s < 0 {
				return nil, protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return out, nil
}

func legacyProtoRule(data []byte) (*config.Rule, error) {
	out := &config.Rule{}
	for len(data) > 0 {
		n, typ, s := protowire.ConsumeTag(data)
		if s < 0 {
			return nil, protowire.ParseError(s)
		}
		data = data[s:]
		if n >= 1 && n <= 6 {
			if typ != protowire.BytesType {
				return nil, fmt.Errorf("rule condition %d has wire type %d", n, typ)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return nil, protowire.ParseError(x)
			}
			switch n {
			case 1:
				z, e := legacyProtoSingleString(v)
				if e != nil {
					return nil, e
				}
				out.SetHost(&config.Host{List: z})
			case 2:
				z, e := legacyProtoSingleString(v)
				if e != nil {
					return nil, e
				}
				out.SetProcess(&config.Process{List: z})
			case 3:
				z, zs, e := legacyProtoSource(v)
				if e != nil {
					return nil, e
				}
				out.SetInbound(&config.Source{Name: z, Names: zs})
			case 4:
				z, e := legacyProtoSingleVarint(v)
				if e != nil {
					return nil, e
				}
				out.SetNetwork(&config.Network{Network: config.NetworkNetworkType(z)})
			case 5:
				z, e := legacyProtoSingleString(v)
				if e != nil {
					return nil, e
				}
				out.SetPort(&config.Port{Ports: z})
			case 6:
				z, e := legacyProtoSingleString(v)
				if e != nil {
					return nil, e
				}
				out.SetGeoip(&config.Geoip{Countries: z})
			}
			data = data[x:]
		} else {
			s = protowire.ConsumeFieldValue(n, typ, data)
			if s < 0 {
				return nil, protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return out, nil
}

func legacyProtoSingleString(data []byte) (string, error) {
	var out string
	for len(data) > 0 {
		n, t, s := protowire.ConsumeTag(data)
		if s < 0 {
			return "", protowire.ParseError(s)
		}
		data = data[s:]
		if n == 1 {
			if t != protowire.BytesType {
				return "", fmt.Errorf("string field has wire type %d", t)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return "", protowire.ParseError(x)
			}
			out = string(v)
			data = data[x:]
		} else {
			s = protowire.ConsumeFieldValue(n, t, data)
			if s < 0 {
				return "", protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return out, nil
}
func legacyProtoSingleVarint(data []byte) (uint64, error) {
	var out uint64
	for len(data) > 0 {
		n, t, s := protowire.ConsumeTag(data)
		if s < 0 {
			return 0, protowire.ParseError(s)
		}
		data = data[s:]
		if n == 1 {
			if t != protowire.VarintType {
				return 0, fmt.Errorf("varint field has wire type %d", t)
			}
			v, x := protowire.ConsumeVarint(data)
			if x < 0 {
				return 0, protowire.ParseError(x)
			}
			out = v
			data = data[x:]
		} else {
			s = protowire.ConsumeFieldValue(n, t, data)
			if s < 0 {
				return 0, protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return out, nil
}
func legacyProtoSource(data []byte) (string, []string, error) {
	var name string
	var names []string
	for len(data) > 0 {
		n, t, s := protowire.ConsumeTag(data)
		if s < 0 {
			return "", nil, protowire.ParseError(s)
		}
		data = data[s:]
		if n == 1 || n == 2 {
			if t != protowire.BytesType {
				return "", nil, fmt.Errorf("source field %d has wire type %d", n, t)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return "", nil, protowire.ParseError(x)
			}
			if n == 1 {
				name = string(v)
			} else {
				names = append(names, string(v))
			}
			data = data[x:]
		} else {
			s = protowire.ConsumeFieldValue(n, t, data)
			if s < 0 {
				return "", nil, protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return name, names, nil
}

func legacyProtoList(data []byte) (*config.List, error) {
	out := &config.List{}
	for len(data) > 0 {
		n, t, s := protowire.ConsumeTag(data)
		if s < 0 {
			return nil, protowire.ParseError(s)
		}
		data = data[s:]
		switch n {
		case 1:
			if t != protowire.VarintType {
				return nil, fmt.Errorf("list type has wire type %d", t)
			}
			v, x := protowire.ConsumeVarint(data)
			if x < 0 {
				return nil, protowire.ParseError(x)
			}
			out.SetListType(config.ListListTypeEnum(v))
			data = data[x:]
		case 2, 5:
			if t != protowire.BytesType {
				return nil, fmt.Errorf("list field %d has wire type %d", n, t)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return nil, protowire.ParseError(x)
			}
			if n == 2 {
				out.SetName(string(v))
			} else {
				out.SetErrorMsgs(append(out.GetErrorMsgs(), string(v)))
			}
			data = data[x:]
		case 3, 4:
			if t != protowire.BytesType {
				return nil, fmt.Errorf("list source has wire type %d", t)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return nil, protowire.ParseError(x)
			}
			values, err := legacyProtoRepeatedStrings(v)
			if err != nil {
				return nil, err
			}
			if n == 3 {
				out.SetLocal(&config.ListLocal{Lists: values})
			} else {
				out.SetRemote(&config.ListRemote{Urls: values})
			}
			data = data[x:]
		default:
			s = protowire.ConsumeFieldValue(n, t, data)
			if s < 0 {
				return nil, protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return out, nil
}
func legacyProtoRepeatedStrings(data []byte) ([]string, error) {
	var out []string
	for len(data) > 0 {
		n, t, s := protowire.ConsumeTag(data)
		if s < 0 {
			return nil, protowire.ParseError(s)
		}
		data = data[s:]
		if n == 1 {
			if t != protowire.BytesType {
				return nil, fmt.Errorf("list value has wire type %d", t)
			}
			v, x := protowire.ConsumeBytes(data)
			if x < 0 {
				return nil, protowire.ParseError(x)
			}
			out = append(out, string(v))
			data = data[x:]
		} else {
			s = protowire.ConsumeFieldValue(n, t, data)
			if s < 0 {
				return nil, protowire.ParseError(s)
			}
			data = data[s:]
		}
	}
	return out, nil
}

// unmarshalLegacyAndroidInboundProto decodes the part of the former
// config.InboundConfig protobuf message that Android persisted independently.
// The listener map is deliberately ignored: Android rebuilt it for each VPN
// start from the current runtime options, rather than using the stored map.
func unmarshalLegacyAndroidInboundProto(data []byte, inbound *config.InboundConfig) error {
	if inbound == nil {
		return errors.New("inbound config is nil")
	}

	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]

		switch number {
		case 1: // inbounds: Android generated these at runtime.
			if typ != protowire.BytesType {
				return fmt.Errorf("inbounds has wire type %d, want bytes", typ)
			}
			_, n = protowire.ConsumeBytes(data)
		case 2:
			if typ != protowire.VarintType {
				return fmt.Errorf("hijack_dns has wire type %d, want varint", typ)
			}
			var value uint64
			value, n = protowire.ConsumeVarint(data)
			if n >= 0 {
				inbound.SetHijackDns(value != 0)
			}
		case 3:
			if typ != protowire.VarintType {
				return fmt.Errorf("hijack_dns_fakeip has wire type %d, want varint", typ)
			}
			var value uint64
			value, n = protowire.ConsumeVarint(data)
			if n >= 0 {
				inbound.SetHijackDnsFakeip(value != 0)
			}
		case 4:
			if typ != protowire.BytesType {
				return fmt.Errorf("sniff has wire type %d, want bytes", typ)
			}
			var sniffData []byte
			sniffData, n = protowire.ConsumeBytes(data)
			if n >= 0 {
				sniff, err := unmarshalLegacyAndroidSniffProto(sniffData)
				if err != nil {
					return err
				}
				inbound.SetSniff(sniff)
			}
		default:
			n = protowire.ConsumeFieldValue(number, typ, data)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
	}
	return nil
}

func unmarshalLegacyAndroidSniffProto(data []byte) (*config.Sniff, error) {
	sniff := &config.Sniff{}
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]

		if number == 1 {
			if typ != protowire.VarintType {
				return nil, fmt.Errorf("sniff enabled has wire type %d, want varint", typ)
			}
			value, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			sniff.SetEnabled(value != 0)
			data = data[n:]
			continue
		}

		n = protowire.ConsumeFieldValue(number, typ, data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
	}
	return sniff, nil
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

func encodeJSONText(msg any) (string, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeJSONText(data string, msg any) error {
	return json.Unmarshal([]byte(data), msg)
}

func decodeJSONValue[T any](data string) (T, error) {
	var value T
	err := json.Unmarshal([]byte(data), &value)
	return value, err
}

func normalizeSetting(setting *config.Setting, dir string) {
	jsondb.MergeDefault(setting, config.DefaultSetting(dir))
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

func applyInboundTypeFallback(inbound *config.Inbound, inboundTypeValue string) {
	if inbound == nil {
		return
	}

	switch inboundTypeValue {
	case "http":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetHttp(&config.Http{})
		}
	case "socks5":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetSocks5(&config.Socks5{})
		}
	case "yuubinsya":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetYuubinsya(&config.Yuubinsya{})
		}
	case "mixed":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetMix(&config.Mixed{})
		}
	case "socks4a":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetSocks4A(&config.Socks4A{})
		}
	case "tproxy":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetTproxy(&config.Tproxy{})
		}
	case "redir":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetRedir(&config.Redir{})
		}
	case "tun":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetTun(&config.Tun{})
		}
	case "reverse_http":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetReverseHttp(&config.ReverseHttp{})
		}
	case "reverse_tcp":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetReverseTcp(&config.ReverseTcp{})
		}
	case "none":
		if inbound.WhichProtocol() == config.Inbound_Protocol_not_set_case {
			inbound.SetNone(&config.Empty{})
		}
	case "tcpudp":
		if inbound.WhichNetwork() == config.Inbound_Network_not_set_case {
			inbound.SetTcpudp(&config.Tcpudp{})
		}
	case "quic":
		if inbound.WhichNetwork() == config.Inbound_Network_not_set_case {
			inbound.SetQuic(&config.Quic{})
		}
	case "empty":
		if inbound.WhichNetwork() == config.Inbound_Network_not_set_case {
			inbound.SetEmpty(&config.Empty{})
		}
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
