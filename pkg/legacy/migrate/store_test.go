package migrate

import (
	"context"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	legacyconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	legacynode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestMigrateLegacyInbounds(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	old := legacyconfig.Inbound_builder{
		Name:    ptr("reversehttp"),
		Enabled: ptr(true),
		Tcpudp: legacyconfig.Tcpudp_builder{
			Host:    ptr(":9002"),
			Control: legacyconfig.TcpUdpControl_disable_udp.Enum(),
		}.Build(),
		ReverseHttp: legacyconfig.ReverseHttp_builder{
			Url: ptr("http://127.0.0.1:3000"),
		}.Build(),
		Transport: []*legacyconfig.Transport{
			legacyconfig.Transport_builder{Normal: legacyconfig.Normal_builder{}.Build()}.Build(),
		},
	}.Build()
	dataJSON, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO inbounds(name, enabled, inbound_type, listen_host, updated_at, data_json)
		VALUES ('reversehttp', 1, 'reverse_http', '', 100, ?)
	`, string(dataJSON)); err != nil {
		t.Fatal(err)
	}

	warnings, err := MigrateLegacyInbounds(ctx, sqliteStore.DB(), 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v", warnings)
	}

	got, err := plainstore.NewInboundStore(sqliteStore.DB()).Get(ctx, "reversehttp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol.Type != contractinbound.ProtocolReverseHTTP || got.Protocol.ReverseHTTP.URL != "http://127.0.0.1:3000" {
		t.Fatalf("migrated inbound = %+v", got)
	}
	assertMarker(t, ctx, sqliteStore, "plain_inbounds_migration_done")
}

func TestRecoverLegacyInboundTransportsFromConfig(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	inbound := contractinbound.Inbound{
		ID:      "http2",
		Name:    "http2",
		Enabled: true,
		Network: contractinbound.NewTypedNetwork(contractinbound.TCPUDPNetwork{Host: ":443", UDP: contractinbound.UDPEnabled}),
		Transports: []contractinbound.Transport{
			contractinbound.NewTypedTransport(contractinbound.TLSAutoTransport{}),
		},
		Protocol: contractinbound.NewTypedProtocol(contractinbound.YuubinsyaProtocol{}),
	}
	if err := plainstore.SaveInboundContract(ctx, sqliteStore.DB(), inbound, 100); err != nil {
		t.Fatal(err)
	}
	config := `{
		"server": {
			"inbounds": {
				"http2": {
					"transport": [
						{"proxy": {}},
						{"http_mock": {"data": null}},
						{"tls_auto": {}},
						{"grpc": {}},
						{"http2": {}},
						{"websocket": {}},
						{"aead": {"password": "secret", "crypto_method": "XChacha20Poly1305"}}
					]
				}
			}
		}
	}`
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := RecoverLegacyInboundTransportsFromConfig(ctx, sqliteStore.DB(), configPath); err != nil {
		t.Fatal(err)
	}
	got, err := plainstore.NewInboundStore(sqliteStore.DB()).Get(ctx, "http2")
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, transport := range got.Transports {
		types = append(types, transport.Type)
	}
	if joined := strings.Join(types, ","); joined != "proxy,http_mock,tls_auto,http2,websocket,aead" {
		t.Fatalf("recovered transports = %q", joined)
	}
	if got.Transports[5].AEAD.Password != "secret" || got.Transports[5].AEAD.CryptoMethod != "XChacha20Poly1305" {
		t.Fatalf("recovered aead = %#v", got.Transports[5].AEAD)
	}
	assertMarker(t, ctx, sqliteStore, inboundTransportRecoveryDoneKey)
}

func TestMigrateLegacyNodesBackfillsWhenMarkerDoneButContractsEmpty(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	point := legacynode.Point_builder{
		Hash:   ptr("hash-1"),
		Name:   ptr("alpha"),
		Group:  ptr("manual"),
		Origin: legacynode.Origin_manual.Enum(),
	}.Build()
	dataJSON, err := json.Marshal(point)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO nodes(hash, group_name, name, origin, selected_tcp, selected_udp, search_text, updated_at, data_json)
		VALUES ('hash-1', 'manual', 'alpha', ?, 1, 1, 'alpha manual', 100, ?)
	`, int(legacynode.Origin_manual), string(dataJSON)); err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO metadata(key, value)
		VALUES ('plain_nodes_migration_done', '1')
	`); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacyNodes(ctx, sqliteStore.DB(), 200); err != nil {
		t.Fatal(err)
	}
	got, err := plainstore.NewNodeStore(sqliteStore.DB()).Get(ctx, "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "hash-1" || got.Name != "alpha" || len(got.Chain) != 1 || got.Chain[0].Type != "direct" {
		t.Fatalf("migrated node = %+v", got)
	}
	assertMetadataValue(t, ctx, sqliteStore, "selected_tcp_node_v2", "hash-1")
	assertMetadataValue(t, ctx, sqliteStore, "selected_udp_node_v2", "hash-1")
}

func TestRecoverLegacyNodeChainsRestoresPartialNetworkSplit(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	password := "secret"
	legacyPoint := legacyconfigPointForPartialNetworkSplit(password)
	legacyJSON, err := json.Marshal(legacyPoint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO nodes(hash, group_name, name, origin, selected_tcp, selected_udp, search_text, updated_at, data_json)
		VALUES ('partial-split', 'manual', 'partial-split', ?, 0, 0, '', 100, ?)
	`, int(legacynode.Origin_manual), string(legacyJSON)); err != nil {
		t.Fatal(err)
	}
	current := contractnode.Node{
		ID:      "partial-split",
		Name:    "partial-split",
		Group:   "manual",
		Origin:  "manual",
		Enabled: true,
		Chain: []contractnode.Protocol{
			mustNodeProtocol(t, contractnode.Yuubinsya{Password: password}),
		},
	}
	if err := plainstore.SaveNodeContract(ctx, sqliteStore.DB(), current, 100); err != nil {
		t.Fatal(err)
	}

	if err := RecoverLegacyNodeChains(ctx, sqliteStore.DB()); err != nil {
		t.Fatal(err)
	}
	got, err := plainstore.NewNodeStore(sqliteStore.DB()).Get(ctx, "partial-split")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Chain) != 2 || got.Chain[0].Type != "network_split" || got.Chain[0].NetworkSplit.UDP == nil || got.Chain[0].NetworkSplit.TCP != nil {
		t.Fatalf("recovered chain = %#v", got.Chain)
	}
	assertMarker(t, ctx, sqliteStore, nodeChainRecoveryDoneKey)
}

func legacyconfigPointForPartialNetworkSplit(password string) *legacynode.Point {
	return legacynode.Point_builder{
		Hash:   ptr("partial-split"),
		Name:   ptr("partial-split"),
		Group:  ptr("manual"),
		Origin: legacynode.Origin_manual.Enum(),
		Protocols: []*legacynode.Protocol{
			legacynode.Protocol_builder{NetworkSplit: legacynode.NetworkSplit_builder{
				Udp: legacynode.Protocol_builder{Aead: legacynode.Aead_builder{
					Password:     &password,
					CryptoMethod: legacynode.AeadCryptoMethod_XChacha20Poly1305.Enum(),
				}.Build()}.Build(),
			}.Build()}.Build(),
			legacynode.Protocol_builder{Yuubinsya: legacynode.Yuubinsya_builder{Password: &password}.Build()}.Build(),
		},
	}.Build()
}

func mustNodeProtocol(t *testing.T, value contractnode.ProtocolPayload) contractnode.Protocol {
	t.Helper()
	protocol, err := contractnode.NewTypedProtocol(value)
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func TestMigrateLegacyNodesDoesNotOverwriteValidSelection(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	for _, item := range []struct {
		hash     string
		name     string
		selected bool
	}{
		{hash: "hash-1", name: "alpha", selected: true},
		{hash: "hash-2", name: "beta"},
	} {
		point := legacynode.Point_builder{
			Hash:   ptr(item.hash),
			Name:   ptr(item.name),
			Group:  ptr("manual"),
			Origin: legacynode.Origin_manual.Enum(),
		}.Build()
		dataJSON, err := json.Marshal(point)
		if err != nil {
			t.Fatal(err)
		}
		selected := 0
		if item.selected {
			selected = 1
		}
		if _, err := sqliteStore.DB().ExecContext(ctx, `
			INSERT INTO nodes(hash, group_name, name, origin, selected_tcp, selected_udp, search_text, updated_at, data_json)
			VALUES (?, 'manual', ?, ?, ?, ?, ?, 100, ?)
		`, item.hash, item.name, int(legacynode.Origin_manual), selected, selected, item.name+" manual", string(dataJSON)); err != nil {
			t.Fatal(err)
		}
		node, warnings, err := ConvertLegacyNode(point)
		if err != nil {
			t.Fatal(err)
		}
		for _, warning := range warnings {
			t.Logf("warning: %s: %s", warning.Entity, warning.Message)
		}
		if err := plainstore.SaveNodeContract(ctx, sqliteStore.DB(), node, 100); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO metadata(key, value)
		VALUES
			('plain_nodes_migration_done', '1'),
			('selected_tcp_node_v2', 'hash-2'),
			('selected_udp_node_v2', 'hash-2')
	`); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacyNodes(ctx, sqliteStore.DB(), 200); err != nil {
		t.Fatal(err)
	}
	assertMetadataValue(t, ctx, sqliteStore, "selected_tcp_node_v2", "hash-2")
	assertMetadataValue(t, ctx, sqliteStore, "selected_udp_node_v2", "hash-2")
}

func TestMigrateLegacyResolvers(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	old := legacyconfig.Dns_builder{
		Host: ptr("dns.google:853"),
		Type: legacyconfig.Type_dot.Enum(),
	}.Build()
	dataJSON, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO dns_resolvers(name, resolver_type, host, subnet, tls_servername, data_json)
		VALUES ('google', ?, 'dns.google:853', '', '', ?)
	`, int(legacyconfig.Type_dot), string(dataJSON)); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyResolvers(ctx, sqliteStore.DB(), 200); err != nil {
		t.Fatal(err)
	}
	got, err := plainstore.NewResolverStore(sqliteStore.DB()).Get(ctx, "google")
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "dot" || got.Host != "dns.google:853" {
		t.Fatalf("migrated resolver = %+v", got)
	}
}

func TestMigrateLegacyRouteRules(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	old := legacyconfig.Rulev2_builder{
		Name: ptr("legacy"),
		Mode: legacyconfig.Mode_bypass.Enum(),
		Tag:  ptr("direct"),
	}.Build()
	dataJSON, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO route_rules(name, priority, disabled, updated_at, data_json)
		VALUES ('legacy', 7, 0, 100, ?)
	`, string(dataJSON)); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacyRouteRules(ctx, sqliteStore.DB(), 200); err != nil {
		t.Fatal(err)
	}
	got, err := plainstore.NewRouteRuleStore(sqliteStore.DB()).GetRule(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if got.Rule.Name != "legacy" || got.Rule.Mode != "bypass" || got.Priority != 1 {
		t.Fatalf("migrated rule = %+v", got)
	}
}

func TestMigrateLegacyRouteRulesRenumbersLegacyPriorities(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	for i, name := range []string{"tailscale", "vrchat"} {
		old := legacyconfig.Rulev2_builder{
			Name: ptr(name),
			Mode: legacyconfig.Mode_bypass.Enum(),
			Tag:  ptr("direct"),
		}.Build()
		dataJSON, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sqliteStore.DB().ExecContext(ctx, `
			INSERT INTO route_rules(name, priority, disabled, updated_at, data_json)
			VALUES (?, ?, 0, 100, ?)
		`, name, 7+i, string(dataJSON)); err != nil {
			t.Fatal(err)
		}
	}

	if err := MigrateLegacyRouteRules(ctx, sqliteStore.DB(), 200); err != nil {
		t.Fatal(err)
	}
	got, err := plainstore.NewRouteRuleStore(sqliteStore.DB()).ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("rules = %+v", got)
	}
	if got[0].Priority != 1 || got[1].Priority != 2 {
		t.Fatalf("renumbered rules = %+v", got)
	}
	if got[0].Rule.Name != "tailscale" || got[1].Rule.Name != "vrchat" {
		t.Fatalf("rule order = %+v", got)
	}
}

func TestMigrateLegacyRouteLists(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	old := legacyconfig.List_builder{
		Name:     ptr("legacy-list"),
		ListType: legacyconfig.List_process.Enum(),
		Local:    legacyconfig.ListLocal_builder{Lists: []string{"proc"}}.Build(),
	}.Build()
	dataJSON, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO route_lists(name, kind, updated_at, data_json)
		VALUES ('legacy-list', 'process', 100, ?)
	`, string(dataJSON)); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyRouteLists(ctx, sqliteStore.DB(), 200); err != nil {
		t.Fatal(err)
	}
	got, err := plainstore.NewRouteListStore(sqliteStore.DB()).GetRouteList(ctx, "legacy-list")
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "process" || got.Source.Local == nil || got.Source.Local.Lists[0] != "proc" {
		t.Fatalf("migrated list = %+v", got)
	}
}

func TestMigrateLegacyRouteTags(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO node_tags(tag_name, target_kind, target_id, updated_at)
		VALUES
			('node-tag', 'node', 'node-a', 100),
			('mirror-tag', 'tag', 'node-tag', 100)
	`); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyRouteTags(ctx, sqliteStore.DB(), 200); err != nil {
		t.Fatal(err)
	}
	got, err := plainstore.NewRouteTagStore(sqliteStore.DB()).ListTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("tags = %+v", got)
	}
	byName := map[string]contractroute.TagItem{}
	for _, item := range got {
		byName[item.Name] = item
	}
	if byName["node-tag"].Type != "node" || byName["node-tag"].Hash[0] != "node-a" {
		t.Fatalf("node tag = %+v", byName["node-tag"])
	}
	if byName["mirror-tag"].Type != "mirror" || byName["mirror-tag"].Hash[0] != "node-tag" {
		t.Fatalf("mirror tag = %+v", byName["mirror-tag"])
	}
}

func TestMigrateLegacyBackupRewritesContractJSON(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO backup_settings(id, updated_at, data_json)
		VALUES (1, 100, ?)
	`, `{
		"instance_name": "legacy-instance",
		"interval": "3600",
		"last_backup_hash": "legacy-hash",
		"s3": {
			"enabled": true,
			"access_key": "access",
			"secret_key": "secret",
			"bucket": "bucket",
			"region": "region",
			"endpoint_url": "https://s3.example.com",
			"use_path_style": true,
			"storage_class": "STANDARD"
		}
	}`); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacyBackup(ctx, sqliteStore.DB(), 200); err != nil {
		t.Fatal(err)
	}

	got, err := plainstore.NewBackupStore(sqliteStore.DB()).Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.InstanceName != "legacy-instance" ||
		got.Interval != 3600 ||
		got.LastBackupHash != "legacy-hash" ||
		!got.S3.Enabled ||
		got.S3.EndpointURL != "https://s3.example.com" ||
		!got.S3.UsePathStyle {
		t.Fatalf("migrated backup = %+v", got)
	}

	var dataJSON string
	if err := sqliteStore.DB().QueryRowContext(ctx, `SELECT data_json FROM backup_settings WHERE id = 1`).Scan(&dataJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dataJSON, `"instanceName"`) ||
		!strings.Contains(dataJSON, `"endpointUrl"`) ||
		!strings.Contains(dataJSON, `"usePathStyle"`) ||
		strings.Contains(dataJSON, `"instance_name"`) ||
		strings.Contains(dataJSON, `"endpoint_url"`) {
		t.Fatalf("backup json was not rewritten to contract shape: %s", dataJSON)
	}
	assertMarker(t, ctx, sqliteStore, "plain_backup_migration_done")

	got.InstanceName = "current-instance"
	if err := plainstore.NewBackupStore(sqliteStore.DB()).Save(ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyBackup(ctx, sqliteStore.DB(), 300); err != nil {
		t.Fatal(err)
	}
	got, err = plainstore.NewBackupStore(sqliteStore.DB()).Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.InstanceName != "current-instance" {
		t.Fatalf("completed backup migration overwrote current settings: %+v", got)
	}
}

func assertMarker(t *testing.T, ctx context.Context, sqliteStore *storagesqlite.Store, key string) {
	t.Helper()
	var marker string
	if err := sqliteStore.DB().QueryRowContext(ctx, `
		SELECT value
		FROM metadata
		WHERE key = ?
	`, key).Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != "1" {
		t.Fatalf("%s = %q", key, marker)
	}
}

func assertMetadataValue(t *testing.T, ctx context.Context, sqliteStore *storagesqlite.Store, key, want string) {
	t.Helper()
	var got string
	if err := sqliteStore.DB().QueryRowContext(ctx, `
		SELECT value
		FROM metadata
		WHERE key = ?
	`, key).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s = %q, want %q", key, got, want)
	}
}
