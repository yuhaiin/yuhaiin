package migrate

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"fmt"
	"path/filepath"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestMigrateLegacyCredentialsIsDeduplicatedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	dbStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dbStore.Close()
	db := dbStore.DB()

	inboundJSON := `{"id":"in-1","name":"legacy inbound","enabled":true,"network":{"type":"empty","empty":{}},"transports":[{"type":"normal","normal":{}}],"protocol":{"type":"http","http":{"username":"alice","password":"secret"}}}`
	if _, err := db.ExecContext(ctx, `
		INSERT INTO inbounds_v2(id, name, enabled, network_type, protocol_type, transport_types_json, updated_at, data_json)
		VALUES ('in-1', 'legacy inbound', 1, 'empty', 'http', '["normal"]', 1, ?)
	`, inboundJSON); err != nil {
		t.Fatal(err)
	}

	node := contractnode.Node{
		ID: "node-1", Name: "legacy node", Group: "local", Origin: "local", Enabled: true,
		Chain: []contractnode.Protocol{{Type: "http", HTTP: &contractnode.HTTP{User: "alice", Password: "secret"}}},
	}
	nodeJSON, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO nodes_v2(id, name, group_name, origin, enabled, chain_types_json, updated_at, data_json)
		VALUES ('node-1', 'legacy node', 'local', 'local', 1, '["http"]', 1, ?)
	`, string(nodeJSON)); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacyCredentials(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyCredentials(ctx, db); err != nil {
		t.Fatal(err)
	}

	if got := scalarInt(t, db, `SELECT COUNT(*) FROM users_v2`); got != 1 {
		t.Fatalf("users = %d, want 1", got)
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM user_migration_sources_v2`); got != 2 {
		t.Fatalf("migration sources = %d, want 2", got)
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM user_migration_dedup_v2`); got != 1 {
		t.Fatalf("migration dedup rows = %d, want 1", got)
	}
	var usage string
	if err := db.QueryRowContext(ctx, `SELECT usage FROM users_v2 LIMIT 1`).Scan(&usage); err != nil {
		t.Fatal(err)
	}
	if usage != "both" {
		t.Fatalf("usage = %q, want both", usage)
	}

	var migrated contractnode.Node
	var migratedJSON string
	if err := db.QueryRowContext(ctx, `SELECT data_json FROM nodes_v2 WHERE id = 'node-1'`).Scan(&migratedJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(migratedJSON), &migrated); err != nil {
		t.Fatal(err)
	}
	if migrated.Chain[0].HTTP.UserID == "" {
		t.Fatal("legacy node userId was not written")
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM user_migration_state_v2 WHERE migration_name = ?`, legacyCredentialMigration).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("migration status = %q, want completed", status)
	}

	// A completed baseline must not prevent a later import of another legacy
	// node. Source mappings, rather than the global state row, are the
	// idempotency boundary.
	later := contractnode.Node{
		ID: "node-2", Name: "later legacy node", Group: "remote", Origin: "remote", Enabled: true,
		Chain: []contractnode.Protocol{{Type: "trojan", Trojan: &contractnode.Trojan{Password: "later-secret"}}},
	}
	laterJSON, err := json.Marshal(later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO nodes_v2(id, name, group_name, origin, enabled, chain_types_json, updated_at, data_json)
		VALUES ('node-2', 'later legacy node', 'remote', 'remote', 1, '["trojan"]', 2, ?)
	`, string(laterJSON)); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyCredentials(ctx, db); err != nil {
		t.Fatal(err)
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM users_v2`); got != 2 {
		t.Fatalf("users after later migration = %d, want 2", got)
	}
	var laterMigrated contractnode.Node
	if err := db.QueryRowContext(ctx, `SELECT data_json FROM nodes_v2 WHERE id = 'node-2'`).Scan(&migratedJSON); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(migratedJSON), &laterMigrated); err != nil {
		t.Fatal(err)
	}
	if laterMigrated.Chain[0].Trojan.UserID == "" {
		t.Fatal("later legacy node was not migrated after completed baseline")
	}
}

func scalarInt(t *testing.T, db *sql.DB, query string) int64 {
	t.Helper()
	var value int64
	if err := db.QueryRow(query).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestMigrateLegacyCredentialProtocolMatrix(t *testing.T) {
	ctx := context.Background()
	dbStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dbStore.Close()
	db := dbStore.DB()

	inbounds := []struct {
		id, protocolType, protocolJSON string
	}{
		{"matrix-http", "http", `{"type":"http","http":{"username":"in-http-user","password":"in-http-pass"}}`},
		{"matrix-socks5", "socks5", `{"type":"socks5","socks5":{"username":"in-socks-user","password":"in-socks-pass","udp":true}}`},
		{"matrix-mixed", "mixed", `{"type":"mixed","mixed":{"username":"in-mixed-user","password":"in-mixed-pass"}}`},
		{"matrix-socks4a", "socks4a", `{"type":"socks4a","socks4a":{"username":"in-socks4-user"}}`},
		{"matrix-yuubinsya", "yuubinsya", `{"type":"yuubinsya","yuubinsya":{"password":"in-yuu-pass"}}`},
		{"matrix-yuubinsya-empty", "yuubinsya", `{"type":"yuubinsya","yuubinsya":{"password":""}}`},
		{"matrix-aead", "none", `{"type":"none","none":{}}`},
	}
	for _, item := range inbounds {
		data := fmt.Sprintf(`{"id":%q,"name":%q,"enabled":true,"network":{"type":"empty","empty":{}},"transports":[{"type":"normal","normal":{}}],"protocol":%s}`, item.id, item.id, item.protocolJSON)
		if item.id == "matrix-aead" {
			data = fmt.Sprintf(`{"id":%q,"name":%q,"enabled":true,"network":{"type":"empty","empty":{}},"transports":[{"type":"aead","aead":{"password":"in-aead-pass","crypto_method":"Chacha20Poly1305"}}],"protocol":%s}`, item.id, item.id, item.protocolJSON)
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO inbounds_v2(id, name, enabled, network_type, protocol_type, transport_types_json, updated_at, data_json)
			VALUES (?, ?, 1, 'empty', ?, '["normal"]', 1, ?)
		`, item.id, item.id, item.protocolType, data); err != nil {
			t.Fatal(err)
		}
	}

	node := contractnode.Node{
		ID: "matrix-node", Name: "matrix node", Group: "local", Origin: "local", Enabled: true,
		Chain: []contractnode.Protocol{
			{Type: "shadowsocks", Shadowsocks: &contractnode.Shadowsocks{Password: "ss-pass"}},
			{Type: "shadowsocksr", Shadowsocksr: &contractnode.Shadowsocksr{Password: "ssr-pass"}},
			{Type: "vmess", Vmess: &contractnode.Vmess{UUID: "00000000-0000-0000-0000-000000000011"}},
			{Type: "vless", Vless: &contractnode.Vless{UUID: "00000000-0000-0000-0000-000000000012"}},
			{Type: "trojan", Trojan: &contractnode.Trojan{Password: "trojan-pass"}},
			{Type: "socks5", Socks5: &contractnode.Socks5{User: "node-socks-user", Password: "node-socks-pass"}},
			{Type: "http", HTTP: &contractnode.HTTP{User: "node-http-user", Password: "node-http-pass"}},
			{Type: "yuubinsya", Yuubinsya: &contractnode.Yuubinsya{Password: "node-yuu-pass"}},
			{Type: "tailscale", Tailscale: &contractnode.Tailscale{AuthKey: "node-token"}},
			{Type: "aead", AEAD: &contractnode.AEAD{Password: "node-aead-pass"}},
			{Type: "network_split", NetworkSplit: &contractnode.NetworkSplit{
				TCP: &contractnode.Protocol{Type: "shadowsocks", Shadowsocks: &contractnode.Shadowsocks{Password: "split-tcp-pass"}},
				UDP: &contractnode.Protocol{Type: "vless", Vless: &contractnode.Vless{UUID: "00000000-0000-0000-0000-000000000013"}},
			}},
			{Type: "wireguard", Wireguard: &contractnode.Wireguard{SecretKey: "wireguard-private-key", Peers: []contractnode.WireguardPeer{{PreSharedKey: "peer-psk"}}}},
			{Type: "cloudflare_warp_masque", CloudflareWarpMasque: &contractnode.CloudflareWarpMasque{PrivateKey: "warp-private-key"}},
		},
	}
	nodeJSON, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO nodes_v2(id, name, group_name, origin, enabled, chain_types_json, updated_at, data_json)
		VALUES ('matrix-node', 'matrix node', 'local', 'local', 1, '[]', 1, ?)
	`, string(nodeJSON)); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacyCredentials(ctx, db); err != nil {
		t.Fatal(err)
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM users_v2`); got != 19 {
		t.Fatalf("matrix users = %d, want 19", got)
	}
	if got := scalarInt(t, db, `SELECT COUNT(*) FROM user_migration_sources_v2`); got != 19 {
		t.Fatalf("matrix sources = %d, want 19", got)
	}

	var migratedJSON string
	if err := db.QueryRowContext(ctx, `SELECT data_json FROM nodes_v2 WHERE id = 'matrix-node'`).Scan(&migratedJSON); err != nil {
		t.Fatal(err)
	}
	var migrated contractnode.Node
	if err := json.Unmarshal([]byte(migratedJSON), &migrated); err != nil {
		t.Fatal(err)
	}
	for i, protocol := range migrated.Chain[:11] {
		if i == 10 {
			if protocol.NetworkSplit == nil || protocol.NetworkSplit.TCP == nil || protocol.NetworkSplit.TCP.Shadowsocks.UserID == "" || protocol.NetworkSplit.UDP == nil || protocol.NetworkSplit.UDP.Vless.UserID == "" {
				t.Fatalf("network split was not migrated: %+v", protocol)
			}
			continue
		}
		if protocolUserID(protocol) == "" {
			t.Fatalf("chain[%d] %s missing userId", i, protocol.Type)
		}
	}
	if migrated.Chain[11].Wireguard.SecretKey != "wireguard-private-key" || migrated.Chain[11].Wireguard.Peers[0].PreSharedKey != "peer-psk" || protocolUserID(migrated.Chain[11]) != "" {
		t.Fatalf("wireguard was incorrectly migrated: %+v", migrated.Chain[11])
	}
	if migrated.Chain[12].CloudflareWarpMasque.PrivateKey != "warp-private-key" || protocolUserID(migrated.Chain[12]) != "" {
		t.Fatalf("warp was incorrectly migrated: %+v", migrated.Chain[12])
	}
}

func protocolUserID(protocol contractnode.Protocol) string {
	switch protocol.Type {
	case "shadowsocks":
		return protocol.Shadowsocks.UserID
	case "shadowsocksr":
		return protocol.Shadowsocksr.UserID
	case "vmess":
		return protocol.Vmess.UserID
	case "vless":
		return protocol.Vless.UserID
	case "trojan":
		return protocol.Trojan.UserID
	case "socks5":
		return protocol.Socks5.UserID
	case "http":
		return protocol.HTTP.UserID
	case "yuubinsya":
		return protocol.Yuubinsya.UserID
	case "tailscale":
		return protocol.Tailscale.UserID
	case "aead":
		return protocol.AEAD.UserID
	default:
		return ""
	}
}
