package chore

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func init() {
	RegisterPlainMigrationHooks(PlainMigrationHooks{
		MigrateLegacyInbounds: func(context.Context, *sql.DB, int64) ([]PlainMigrationWarning, error) {
			return nil, nil
		},
		ImportLegacyNodes:          func(context.Context, *sql.DB, string, int64) error { return nil },
		MigrateLegacyNodes:         func(context.Context, *sql.DB, int64) error { return nil },
		MigrateLegacySubscriptions: func(context.Context, *sql.DB, int64) error { return nil },
		MigrateLegacyResolvers:     func(context.Context, *sql.DB, int64) error { return nil },
		MigrateLegacyRouteRules:    func(context.Context, *sql.DB, int64) error { return nil },
		MigrateLegacyRouteLists:    func(context.Context, *sql.DB, int64) error { return nil },
		MigrateLegacyRouteTags:     func(context.Context, *sql.DB, int64) error { return nil },
		ConvertLegacyInbound: func(name string, inbound *config.Inbound) (contractinbound.Inbound, []PlainMigrationWarning, error) {
			out := contractinbound.Inbound{
				ID:      name,
				Name:    name,
				Enabled: inbound.GetEnabled(),
				Network: contractinbound.NewTypedNetwork(contractinbound.EmptyNetwork{}),
				Transports: []contractinbound.Transport{
					contractinbound.NewTypedTransport(contractinbound.NormalTransport{}),
				},
				Protocol: contractinbound.NewTypedProtocol(contractinbound.NoneProtocol{}),
			}
			if tcpudp := inbound.GetTcpudp(); tcpudp != nil {
				out.Network = contractinbound.NewTypedNetwork(contractinbound.TCPUDPNetwork{
					Host: tcpudp.GetHost(),
					UDP:  contractinbound.UDPEnabled,
				})
			}
			if mixed := inbound.GetMix(); mixed != nil {
				out.Protocol = contractinbound.NewTypedProtocol(contractinbound.MixedProtocol{
					Username: mixed.GetUsername(),
					Password: mixed.GetPassword(),
				})
			}
			return out, nil, nil
		},
	})
}

func TestSqliteDBImportsLegacyConfigAndAndroidPreferences(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	legacy := config.DefaultSetting(dir)
	legacy.SetIpv6(false)
	legacy.GetDns().SetServer("1.1.1.1:5353")
	legacy.GetBypass().SetDirectResolver("legacy-direct")
	legacy.SetBackup(config.BackupOption_builder{
		Interval: new(uint64(12)),
	}.Build())

	configBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy config failed: %v", err)
	}

	if err := os.WriteFile(paths.PathGenerator.Config(dir), configBytes, 0o600); err != nil {
		t.Fatalf("write legacy config failed: %v", err)
	}

	androidConfig := &legacyAndroidMemoryStore{
		Bools: legacySingleStore[bool]{Values: map[string]bool{"allow_lan": true}},
		Ints:  legacySingleStore[int32]{Values: map[string]int32{"android_http_port": 2080}},
		Bytes: legacySingleStore[[]byte]{Values: map[string][]byte{}},
	}

	androidResolver := config.DefaultSetting(dir).GetDns()
	androidResolver.SetServer("9.9.9.9:53")
	androidResolver.GetResolver()["android-bootstrap"] = config.Dns_builder{
		Host: new("9.9.9.9"),
		Type: config.Type_udp.Enum(),
	}.Build()

	resolverBytes, err := json.Marshal(androidResolver)
	if err != nil {
		t.Fatalf("marshal android resolver db failed: %v", err)
	}
	androidConfig.Bytes.Values["resolver_db"] = resolverBytes

	androidConfigBytes, err := json.Marshal(androidConfig)
	if err != nil {
		t.Fatalf("marshal android config store failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "yuhaiin_memory_config_store.json"), androidConfigBytes, 0o600); err != nil {
		t.Fatalf("write android config store failed: %v", err)
	}

	androidPrefsBytes, err := json.Marshal(&legacyAndroidMemoryStore{
		Strings: legacySingleStore[string]{Values: map[string]string{"profile": "balanced"}},
		Bools:   legacySingleStore[bool]{Values: map[string]bool{"allow_lan": true}},
		Ints:    legacySingleStore[int32]{Values: map[string]int32{"yuhaiin_port": 5000}},
	})
	if err != nil {
		t.Fatalf("marshal android preferences failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "yuhaiin_memory_store.json"), androidPrefsBytes, 0o600); err != nil {
		t.Fatalf("write android preferences failed: %v", err)
	}

	db := NewSqliteDB(paths.PathGenerator.State(dir))
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite config failed: %v", err)
	}

	if err := db.View(func(s *config.Setting) error {
		if s.GetIpv6() {
			t.Fatalf("expected imported ipv6=false, got true")
		}
		if got := s.GetDns().GetServer(); got != "9.9.9.9:53" {
			t.Fatalf("expected android resolver override, got %q", got)
		}
		if got := s.GetBypass().GetDirectResolver(); got != "legacy-direct" {
			t.Fatalf("expected bypass direct resolver %q, got %q", "legacy-direct", got)
		}
		if got := s.GetBackup().GetInterval(); got != 12 {
			t.Fatalf("expected backup interval 12, got %d", got)
		}
		if _, ok := s.GetDns().GetResolver()["android-bootstrap"]; !ok {
			t.Fatalf("expected android resolver entry to be imported")
		}
		return nil
	}); err != nil {
		t.Fatalf("view imported sqlite config failed: %v", err)
	}

	store, err := storagesqlite.Open(context.Background(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("open sqlite store for verification failed: %v", err)
	}
	defer store.Close()

	var valueJSON string
	if err := store.DB().QueryRowContext(context.Background(), `
		SELECT value_json
		FROM android_extra_preferences
		WHERE key = 'profile'
	`).Scan(&valueJSON); err != nil {
		t.Fatalf("query imported android preference failed: %v", err)
	}
	if valueJSON != `"balanced"` {
		t.Fatalf("expected imported profile preference, got %q", valueJSON)
	}
}

func TestUnmarshalLegacyAndroidInboundProto(t *testing.T) {
	data := protowire.AppendTag(nil, 2, protowire.VarintType)
	data = protowire.AppendVarint(data, 1)
	data = protowire.AppendTag(data, 3, protowire.VarintType)
	data = protowire.AppendVarint(data, 1)
	sniff := protowire.AppendTag(nil, 1, protowire.VarintType)
	sniff = protowire.AppendVarint(sniff, 1)
	data = protowire.AppendTag(data, 4, protowire.BytesType)
	data = protowire.AppendBytes(data, sniff)

	inbound := config.DefaultSetting(t.TempDir()).GetServer()
	if err := unmarshalLegacyAndroidInboundProto(data, inbound); err != nil {
		t.Fatalf("unmarshal legacy inbound protobuf: %v", err)
	}
	if !inbound.GetHijackDns() || !inbound.GetHijackDnsFakeip() || !inbound.GetSniff().GetEnabled() {
		t.Fatalf("unexpected migrated inbound settings: %+v", inbound)
	}
}

func TestUnmarshalLegacyAndroidBypassProtoRulesAndLists(t *testing.T) {
	data := legacyBypassRulesListsFixture()
	out := config.DefaultSetting(t.TempDir()).GetBypass()
	if err := unmarshalLegacyAndroidBypassProto(data, out); err != nil {
		t.Fatalf("unmarshal legacy bypass protobuf: %v", err)
	}
	if len(out.GetRulesV2()) != 1 || out.GetRulesV2()[0].GetName() != "block ads" {
		t.Fatalf("unexpected migrated rules: %+v", out.GetRulesV2())
	}
	gotHost := out.GetRulesV2()[0].GetRules()[0].GetRules()[0].GetHost().GetList()
	if gotHost != "blocked-hosts" {
		t.Fatalf("host list reference = %q", gotHost)
	}
	gotList := out.GetLists()["blocked-hosts"]
	if gotList == nil || gotList.GetLocal() == nil || len(gotList.GetLocal().GetLists()) != 2 {
		t.Fatalf("unexpected migrated list: %+v", gotList)
	}
}

func TestSaveDNSTxDeduplicatesFakeDNSLists(t *testing.T) {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	dns := config.DefaultSetting(t.TempDir()).GetDns()
	dns.SetFakednsWhitelist([]string{"*.msftncsi.com", "*.msftncsi.com"})
	dns.SetFakednsSkipCheckList([]string{"localhost", "localhost"})
	if err := saveDNSTx(ctx, tx, dns, 1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM dns_fakedns_lists`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("deduplicated DNS list count = %d, want 2", count)
	}
}

func legacyBypassRulesListsFixture() []byte {
	bytesField := func(number protowire.Number, value []byte) []byte {
		data := protowire.AppendTag(nil, number, protowire.BytesType)
		return protowire.AppendBytes(data, value)
	}
	stringField := func(number protowire.Number, value string) []byte {
		return bytesField(number, []byte(value))
	}
	varintField := func(number protowire.Number, value uint64) []byte {
		data := protowire.AppendTag(nil, number, protowire.VarintType)
		return protowire.AppendVarint(data, value)
	}

	host := stringField(1, "blocked-hosts")
	condition := bytesField(1, host)
	orGroup := bytesField(1, condition)
	rule := append(stringField(1, "block ads"), varintField(2, 2)...)
	rule = append(rule, bytesField(7, orGroup)...)

	local := append(stringField(1, "ads.example"), stringField(1, "tracker.example")...)
	list := append(varintField(1, 0), stringField(2, "blocked-hosts")...)
	list = append(list, bytesField(3, local)...)
	listEntry := append(stringField(1, "blocked-hosts"), bytesField(2, list)...)

	return append(bytesField(12, rule), bytesField(13, listEntry)...)
}

func TestRepairsAndroidProtobufConfigAfterPriorImport(t *testing.T) {
	dir := t.TempDir()
	data, err := json.Marshal(&legacyAndroidMemoryStore{Bytes: legacySingleStore[[]byte]{Values: map[string][]byte{
		"bypass_db": legacyBypassRulesListsFixture(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "yuhaiin_memory_config_store.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := storagesqlite.Open(context.Background(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`INSERT INTO metadata(key, value) VALUES ('legacy_config_import_done', '1')`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	db := NewSqliteDB(paths.PathGenerator.State(dir))
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	var rules, lists int
	if err := db.store.DB().QueryRow(`SELECT COUNT(*) FROM route_rules WHERE name = 'block ads'`).Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if err := db.store.DB().QueryRow(`SELECT COUNT(*) FROM route_lists WHERE name = 'blocked-hosts'`).Scan(&lists); err != nil {
		t.Fatal(err)
	}
	if rules != 1 || lists != 1 {
		var allRules, allLists int
		_ = db.store.DB().QueryRow(`SELECT COUNT(*) FROM route_rules`).Scan(&allRules)
		_ = db.store.DB().QueryRow(`SELECT COUNT(*) FROM route_lists`).Scan(&allLists)
		t.Fatalf("repaired route rows: rules=%d/%d lists=%d/%d", rules, allRules, lists, allLists)
	}
}

func TestApplyLegacyAndroidConfigStoreIgnoresUnreadableBlobs(t *testing.T) {
	dir := t.TempDir()
	store := &legacyAndroidMemoryStore{
		Bytes: legacySingleStore[[]byte]{Values: map[string][]byte{
			"chore_db":    {0x04},
			"resolver_db": {0x04},
			"bypass_db":   {0x04},
			"backup_db":   {0x04},
		}},
	}
	data, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "yuhaiin_memory_config_store.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := applyLegacyAndroidConfigStore(path, config.DefaultSetting(dir), dir); err != nil {
		t.Fatalf("unreadable legacy backup blob should not block migration: %v", err)
	}
}

func TestSqliteDBBatchPersistsAcrossReopen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := paths.PathGenerator.State(dir)

	db := NewSqliteDB(path)
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite config failed: %v", err)
	}

	err := db.Batch(func(s *config.Setting) error {
		s.SetIpv6(false)
		s.SetUseDefaultInterface(false)
		s.SetNetInterface("wlan0")

		s.GetSystemProxy().SetHttp(false)
		s.GetSystemProxy().SetSocks5(true)

		s.GetLogcat().SetLevel(config.LogLevel_warning)
		s.GetLogcat().SetIgnoreDnsError(true)
		s.GetAdvancedConfig().SetUdpBufferSize(4096)
		s.GetAdvancedConfig().SetHappyeyeballsSemaphore(32)

		s.GetDns().SetServer("127.0.0.1:1053")
		s.GetDns().SetResolver(map[string]*config.Dns{
			"bootstrap": config.Dns_builder{
				Host: new("8.8.8.8"),
				Type: config.Type_udp.Enum(),
			}.Build(),
			"remote": config.Dns_builder{
				Host:          new("https://1.1.1.1/dns-query"),
				Type:          config.Type_doh.Enum(),
				TlsServername: new("cloudflare-dns.com"),
			}.Build(),
		})
		s.GetDns().SetHosts(map[string]string{"example.org": "1.2.3.4"})
		s.GetDns().SetFakednsWhitelist([]string{"*.example.org"})
		s.GetDns().SetFakednsSkipCheckList([]string{"skip.example.org"})

		s.GetBypass().SetDirectResolver("bootstrap")
		s.GetBypass().SetProxyResolver("remote")
		s.GetBypass().SetResolveLocally(true)
		s.GetBypass().SetUdpProxyFqdn(config.UdpProxyFqdnStrategy_skip_resolve)
		s.GetBypass().SetRulesV2([]*config.Rulev2{
			config.Rulev2_builder{
				Name:     new("test-rule"),
				Disabled: new(true),
				Mode:     config.Mode_direct.Enum(),
				Tag:      new("LAN"),
			}.Build(),
		})
		s.GetBypass().SetLists(map[string]*config.List{
			"test-list": config.List_builder{
				Name:     new("test-list"),
				ListType: config.List_host.Enum(),
				Local: config.ListLocal_builder{
					Lists: []string{"example.org"},
				}.Build(),
			}.Build(),
		})
		s.GetBypass().SetMaxminddbGeoip(config.MaxminddbGeoip_builder{
			DownloadUrl: new("https://example.com/geoip.mmdb"),
			Error:       new(""),
		}.Build())
		s.GetBypass().SetRefreshConfig(config.RefreshConfig_builder{
			RefreshInterval: new(uint64(3600)),
			LastRefreshTime: new(uint64(100)),
		}.Build())

		s.GetServer().SetHijackDns(false)
		s.GetServer().SetHijackDnsFakeip(false)
		s.GetServer().SetSniff(config.Sniff_builder{Enabled: new(false)}.Build())
		s.GetServer().SetInbounds(map[string]*config.Inbound{
			"mixed": config.Inbound_builder{
				Name:    new("stale-name"),
				Enabled: new(true),
				Tcpudp: config.Tcpudp_builder{
					Host:    new("127.0.0.1:1081"),
					Control: config.TcpUdpControl_tcp_udp_control_all.Enum(),
				}.Build(),
				Mix: &config.Mixed{},
			}.Build(),
		})

		s.SetBackup(config.BackupOption_builder{
			Interval: new(uint64(30)),
		}.Build())

		return nil
	})
	if err != nil {
		t.Fatalf("batch sqlite config failed: %v", err)
	}

	reopened := NewSqliteDB(path)
	if err := reopened.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate reopened sqlite config failed: %v", err)
	}
	if err := reopened.View(func(s *config.Setting) error {
		if s.GetIpv6() {
			t.Fatalf("expected ipv6=false after reopen")
		}
		if s.GetUseDefaultInterface() {
			t.Fatalf("expected use_default_interface=false after reopen")
		}
		if got := s.GetNetInterface(); got != "wlan0" {
			t.Fatalf("expected net interface wlan0, got %q", got)
		}
		if s.GetSystemProxy().GetHttp() {
			t.Fatalf("expected http system proxy disabled")
		}
		if !s.GetSystemProxy().GetSocks5() {
			t.Fatalf("expected socks5 system proxy enabled")
		}
		if got := s.GetLogcat().GetLevel(); got != config.LogLevel_warning {
			t.Fatalf("expected warn log level, got %v", got)
		}
		if got := s.GetAdvancedConfig().GetUdpBufferSize(); got != 4096 {
			t.Fatalf("expected udp buffer size 4096, got %d", got)
		}
		if got := s.GetAdvancedConfig().GetHappyeyeballsSemaphore(); got != 32 {
			t.Fatalf("expected happyeyeballs semaphore 32, got %d", got)
		}
		if got := s.GetDns().GetServer(); got != "127.0.0.1:1053" {
			t.Fatalf("expected dns server 127.0.0.1:1053, got %q", got)
		}
		if _, ok := s.GetDns().GetResolver()["remote"]; !ok {
			t.Fatalf("expected persisted remote resolver")
		}
		if got := s.GetBypass().GetProxyResolver(); got != "remote" {
			t.Fatalf("expected persisted proxy resolver remote, got %q", got)
		}
		if got := len(s.GetBypass().GetRulesV2()); got != 1 {
			t.Fatalf("expected 1 route rule, got %d", got)
		}
		if got := s.GetBypass().GetRefreshConfig().GetRefreshInterval(); got != 3600 {
			t.Fatalf("expected refresh interval 3600, got %d", got)
		}
		if got := len(s.GetServer().GetInbounds()); got != 1 {
			t.Fatalf("expected 1 inbound after reopen, got %d", got)
		}
		if got := s.GetServer().GetInbounds()["mixed"].GetName(); got != "mixed" {
			t.Fatalf("expected inbound name normalized to row key mixed, got %q", got)
		}
		if got := s.GetBackup().GetInterval(); got != 30 {
			t.Fatalf("expected backup interval 30, got %d", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("view reopened sqlite config failed: %v", err)
	}
}

func TestApplyInboundTypeFallback(t *testing.T) {
	inbound := &config.Inbound{}
	applyInboundTypeFallback(inbound, "reverse_tcp")
	if inbound.WhichProtocol() != config.Inbound_ReverseTcp_case {
		t.Fatalf("WhichProtocol = %v, want %v", inbound.WhichProtocol(), config.Inbound_ReverseTcp_case)
	}

	inbound = &config.Inbound{}
	applyInboundTypeFallback(inbound, "mixed")
	if inbound.WhichProtocol() != config.Inbound_Mix_case {
		t.Fatalf("WhichProtocol = %v, want %v", inbound.WhichProtocol(), config.Inbound_Mix_case)
	}

	inbound = &config.Inbound{}
	applyInboundTypeFallback(inbound, "tcpudp")
	if inbound.WhichNetwork() != config.Inbound_Tcpudp_case {
		t.Fatalf("WhichNetwork = %v, want %v", inbound.WhichNetwork(), config.Inbound_Tcpudp_case)
	}
}
