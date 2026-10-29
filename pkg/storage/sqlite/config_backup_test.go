package sqlite

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"path/filepath"
	"strings"
	"testing"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
)

func TestConfigurationExportOmitsS3SecretsAndDisablesAutomaticBackup(t *testing.T) {
	source, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	settings := `{"instanceName":"fixture","interval":30,"lastBackupHash":"digest-marker","s3":{"enabled":true,"accessKey":"config-access-marker","secretKey":"config-secret-marker","bucket":"example"},"recovery":{"enabled":true,"allowMaintenance":true,"localPoints":{"enabled":true,"keepCount":2}}}`
	if _, err := source.DB().ExecContext(t.Context(), `INSERT INTO backup_settings(id,updated_at,data_json) VALUES(1,1,?)`, settings); err != nil {
		t.Fatal(err)
	}
	data, err := ExportConfig(t.Context(), source.DB())
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"config-access-marker", "config-secret-marker", "digest-marker"} {
		if bytes.Contains(data, []byte(marker)) {
			t.Errorf("configuration export includes %s", marker)
		}
	}
	target, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := RestoreConfig(t.Context(), target.DB(), data); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := target.DB().QueryRowContext(t.Context(), `SELECT data_json FROM backup_settings WHERE id=1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var restored contractbackup.Option
	if err := json.Unmarshal([]byte(raw), &restored); err != nil {
		t.Fatal(err)
	}
	if restored.S3.Enabled || restored.Recovery == nil || restored.Recovery.Enabled || restored.Recovery.AllowMaintenance || restored.Recovery.LocalPoints == nil || restored.Recovery.LocalPoints.Enabled {
		t.Fatal("restoring configuration enabled automatic or destructive maintenance", raw)
	}
}

func TestConfigurationExportOmitsSubscriptionCredentialsAndDisarmsPublish(t *testing.T) {
	source, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, statement := range []string{
		`INSERT INTO subscriptions(name,updated_at,data_json) VALUES('upstream',1,'{"name":"upstream","url":"https://example.com/secret-url-path-marker","type":"reserve"}')`,
		`INSERT INTO publishes(name,updated_at,data_json) VALUES('publication',1,'{"name":"publication","password":"publish-password-marker","path":"publish-path-marker","points":["node-id"],"address":"example.com","insecure":false}')`,
	} {
		if _, err := source.DB().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	data, err := ExportConfig(t.Context(), source.DB())
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"secret-url-path-marker", "publish-password-marker", "publish-path-marker"} {
		if bytes.Contains(data, []byte(marker)) {
			t.Fatalf("configuration export contains %s", marker)
		}
	}
	target, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := target.DB().ExecContext(t.Context(), `INSERT INTO subscriptions(name,updated_at,data_json) VALUES('previous',1,'{"name":"previous","url":"https://previous.example/old-secret","type":"reserve"}')`); err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(t.Context(), target.DB(), data); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := target.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM subscriptions`).Scan(&count); err != nil || count != 0 {
		t.Fatal("subscription URL was retained", count, err)
	}
	var raw string
	if err := target.DB().QueryRowContext(t.Context(), `SELECT data_json FROM publishes WHERE name='publication'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var publish struct {
		Password string   `json:"password"`
		Path     string   `json:"path"`
		Points   []string `json:"points"`
	}
	if err := json.Unmarshal([]byte(raw), &publish); err != nil {
		t.Fatal(err)
	}
	if publish.Password != "" || publish.Path != "" || len(publish.Points) != 0 {
		t.Fatal("import could expose the protected publication", raw)
	}
	if err := source.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM subscriptions`).Scan(&count); err != nil || count != 1 {
		t.Fatal("live subscriptions were changed", count, err)
	}
}

func TestConfigurationRestoreReplacesSubscriptionsFromLegacyBackup(t *testing.T) {
	source, err := Open(t.Context(), filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	data, err := ExportConfig(t.Context(), source.DB())
	if err != nil {
		t.Fatal(err)
	}
	var legacy ConfigBackup
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	table := legacy.Tables["subscriptions"]
	name, _ := json.Marshal("upstream")
	document, _ := json.Marshal(`{"name":"upstream","url":"https://example.org/legacy-token","type":"reserve"}`)
	table.Rows = [][]jsontext.Value{{name, jsontext.Value("1"), document}}
	legacy.Tables["subscriptions"] = table
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	target, err := Open(t.Context(), filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := target.DB().ExecContext(t.Context(), `INSERT INTO subscriptions(name,updated_at,data_json) VALUES('upstream',1,'{"name":"upstream","url":"https://old.example","type":"reserve"}')`); err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(t.Context(), target.DB(), data); err != nil {
		t.Fatalf("legacy backup import: %v", err)
	}
	var restored string
	if err := target.DB().QueryRowContext(t.Context(), `SELECT data_json FROM subscriptions WHERE name='upstream'`).Scan(&restored); err != nil || !strings.Contains(restored, "legacy-token") {
		t.Fatal("legacy subscription not restored", restored, err)
	}
}

func TestConfigurationExportRedactsWireGuardIdentityAndDisablesNode(t *testing.T) {
	source, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	doc := `{"id":"wg","name":"WireGuard","origin":"manual","enabled":true,"chain":[{"type":"wireguard","wireguard":{"secretKey":"private-key-marker","endpoint":["vpn.example:1234"],"peers":[{"publicKey":"public","preSharedKey":"preshared-key-marker","endpoint":"vpn.example:1234"}]}}]}`
	if _, err := source.DB().ExecContext(t.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('wg','WireGuard','','manual',1,'["wireguard"]',0,?)`, doc); err != nil {
		t.Fatal(err)
	}
	data, err := ExportConfig(t.Context(), source.DB())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("private-key-marker")) || bytes.Contains(data, []byte("preshared-key-marker")) {
		t.Fatal("configuration export contains WireGuard private credentials")
	}
	target, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := RestoreConfig(t.Context(), target.DB(), data); err != nil {
		t.Fatal(err)
	}
	var enabled int
	var restored string
	if err := target.DB().QueryRowContext(t.Context(), `SELECT enabled,data_json FROM nodes_v2 WHERE id='wg'`).Scan(&enabled, &restored); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 || !bytes.Contains([]byte(restored), []byte(`"enabled":false`)) || !bytes.Contains([]byte(restored), []byte("vpn.example:1234")) {
		t.Fatal("redacted node must be disabled while retaining its endpoint", enabled, restored)
	}
}

func TestConfigurationExportRedactsEmbeddedNodeCredentials(t *testing.T) {
	for _, tc := range []struct{ name, protocol string }{
		{"ssh", `{"type":"ssh","ssh":{"user":"alice","password":"identity-marker","private_key":"identity-marker","private_key_passphrase":"identity-marker","host_key":"public"}}`},
		{"vmess", `{"type":"vmess","vmess":{"id":"identity-marker","aid":"0","security":"auto"}}`},
		{"vless", `{"type":"vless","vless":{"uuid":"identity-marker"}}`},
		{"hysteria2", `{"type":"hysteria2","hysteria2":{"host":"vpn.example","auth":"identity-marker","salamander_password":"identity-marker"}}`},
		{"openvpn", `{"type":"openvpn","openvpn":{"gateway":"vpn.example","password":"identity-marker","client_key_pem":"identity-marker","tls_auth_key":"identity-marker","tls_crypt_key":"identity-marker","auth":"SHA256"}}`},
		{"nebula", `{"type":"nebula","nebula":{"config_yaml":"private_key: identity-marker"}}`},
		{"tls", `{"type":"tls_termination","tls_termination":{"tls":{"certificates":[{"cert":"cHVibGlj","key":"identity-marker"}]}}}`},
		{"network split", `{"type":"network_split","network_split":{"tcp":{"type":"tailscale","tailscale":{"auth_key":"identity-marker"}}}}`},
		{"escaped key", `{"type":"wireguard","wireguard":{"secr\u0065tKey":"identity-marker"}}`},
		{"legacy field casing", `{"type":"wireguard","wireguard":{"Private_Key":"identity-marker","Pre_Shared_Key":"identity-marker"}}`},
		{"url credentials", `{"type":"masque","masque":{"url":"https://user:identity-marker@vpn.example/connect?token=identity-marker#identity-marker"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			doc := `{"id":"node","name":"Fixture","origin":"manual","enabled":true,"chain":[` + tc.protocol + `]}`
			if _, err := source.DB().ExecContext(t.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('node','Fixture','','manual',1,'[]',0,?)`, doc); err != nil {
				t.Fatal(err)
			}
			data, err := ExportConfig(t.Context(), source.DB())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("identity-marker")) {
				t.Fatal("credential remained in configuration export")
			}
			if tc.name == "openvpn" && !bytes.Contains(data, []byte("SHA256")) {
				t.Fatal("non-secret OpenVPN algorithm was removed")
			}
			target, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if err := RestoreConfig(t.Context(), target.DB(), data); err != nil {
				t.Fatal(err)
			}
			var enabled int
			if err := target.DB().QueryRowContext(t.Context(), `SELECT enabled FROM nodes_v2 WHERE id='node'`).Scan(&enabled); err != nil || enabled != 0 {
				t.Fatal("redacted node remained enabled", enabled, err)
			}
		})
	}
}

func TestConfigurationExportRedactsInboundIdentityAndDisablesListener(t *testing.T) {
	source, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	doc := `{"id":"listener","name":"Listener","enabled":true,"network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:1080","udp":"enabled"}},"transports":[{"type":"reality","reality":{"privateKey":"inbound-private-marker","mldsa65Seed":"inbound-seed-marker"}},{"type":"tls_auto","tls_auto":{"caKeyBase64":"inbound-ca-marker"}}],"protocol":{"type":"wireguard","wireguard":{"privateKey":"inbound-wire-marker","peers":[{"preSharedKey":"inbound-psk-marker"}]}},"authentication":{"users":["user-id-marker"]}}`
	if _, err := source.DB().ExecContext(t.Context(), `INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,updated_at,data_json) VALUES('listener','Listener',1,'tcp_udp','wireguard','[]',0,?)`, doc); err != nil {
		t.Fatal(err)
	}
	data, err := ExportConfig(t.Context(), source.DB())
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"inbound-private-marker", "inbound-seed-marker", "inbound-ca-marker", "inbound-wire-marker", "inbound-psk-marker", "user-id-marker"} {
		if bytes.Contains(data, []byte(marker)) {
			t.Errorf("configuration export contains %s", marker)
		}
	}
	target, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := RestoreConfig(t.Context(), target.DB(), data); err != nil {
		t.Fatal(err)
	}
	var enabled int
	var restored string
	if err := target.DB().QueryRowContext(t.Context(), `SELECT enabled,data_json FROM inbounds_v2 WHERE id='listener'`).Scan(&enabled, &restored); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 || !bytes.Contains([]byte(restored), []byte(`"enabled":false`)) || !bytes.Contains([]byte(restored), []byte("127.0.0.1:1080")) {
		t.Fatal("redacted listener must remain disabled with its address", enabled, restored)
	}
}

func TestConfigurationExportRedactsLegacyEndpointCopies(t *testing.T) {
	source, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, query := range []string{
		`INSERT INTO nodes(hash,group_name,name,origin,selected_tcp,search_text,updated_at,data_json) VALUES('legacy','fixture','Legacy',1,1,'legacy-search-marker',1,'{"name":"Legacy","protocols":[{"wireguard":{"secretKey":"legacy-node-key-marker"}}]}')`,
		`INSERT INTO inbounds(name,enabled,inbound_type,listen_host,updated_at,data_json) VALUES('legacy-inbound',1,'http','127.0.0.1:1080',1,'{"name":"legacy-inbound","http":{"password":"legacy-inbound-password-marker"}}')`,
	} {
		if _, err := source.DB().ExecContext(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
	data, err := ExportConfig(t.Context(), source.DB())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"legacy-node-key-marker", "legacy-inbound-password-marker", "legacy-search-marker"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("legacy configuration export includes %s", secret)
		}
	}
	target, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := RestoreConfig(t.Context(), target.DB(), data); err != nil {
		t.Fatal(err)
	}
	var selected, enabled int
	if err := target.DB().QueryRowContext(t.Context(), `SELECT selected_tcp FROM nodes WHERE hash='legacy'`).Scan(&selected); err != nil || selected != 0 {
		t.Fatal("redacted legacy node stayed selected", selected, err)
	}
	if err := target.DB().QueryRowContext(t.Context(), `SELECT enabled FROM inbounds WHERE name='legacy-inbound'`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatal("redacted legacy listener stayed enabled", enabled, err)
	}
}

func TestConfigurationExportRejectsAmbiguousCredentialFields(t *testing.T) {
	db, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	doc := `{"id":"ambiguous","enabled":true,"chain":[{"type":"wireguard","wireguard":{"secretKey":"first-secret","secretKey":"second-secret"}}]}`
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('ambiguous','Ambiguous','','manual',1,'[]',0,?)`, doc); err != nil {
		t.Fatal(err)
	}
	if data, err := ExportConfig(t.Context(), db.DB()); err == nil || len(data) != 0 {
		t.Fatal("ambiguous duplicate credential fields were exported")
	}
}

func TestConfigurationExportRejectsUnknownGatewayFields(t *testing.T) {
	source, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.DB().ExecContext(t.Context(), `INSERT INTO gateway_configuration(id,revision,data_json) VALUES(1,1,'{"version":2,"revision":1,"gateways":[],"futureCredentials":"sensitive-value"}')`); err != nil {
		t.Fatal(err)
	}
	if data, err := ExportConfig(t.Context(), source.DB()); err == nil || len(data) != 0 {
		t.Fatal("export accepted unknown gateway data that may contain credentials")
	}
}

func TestConfigurationExportDisablesGatewayWithRedactedFallback(t *testing.T) {
	source, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	doc := `{"version":2,"revision":1,"gateways":[{"id":"g","name":"Gateway","enabled":true,"revision":1,"policies":[],"backendPools":[],"filters":[],"fallback":{"type":"forward","rewrite":{"query":"token=query-marker","headers":{"X-Api-Key":["header-marker"]}}}}]}`
	if _, err := source.DB().ExecContext(t.Context(), `INSERT INTO gateway_configuration(id,revision,data_json) VALUES(1,1,?)`, doc); err != nil {
		t.Fatal(err)
	}
	data, err := ExportConfig(t.Context(), source.DB())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("query-marker")) || bytes.Contains(data, []byte("header-marker")) {
		t.Fatal("configuration export contains fallback credentials")
	}
	target, err := Open(t.Context(), filepath.Join(t.TempDir(), "target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := RestoreConfig(t.Context(), target.DB(), data); err != nil {
		t.Fatal(err)
	}
	var enabled int
	if err := target.DB().QueryRowContext(t.Context(), `SELECT json_extract(data_json,'$.gateways[0].enabled') FROM gateway_configuration WHERE id=1`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatal("redacted gateway fallback remained enabled", enabled, err)
	}
}

func TestConfigurationExportRejectsExcessivelyNestedEndpoint(t *testing.T) {
	db, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	doc := `{"id":"nested","enabled":true,"value":` + strings.Repeat("[", 65) + `"secret"` + strings.Repeat("]", 65) + `}`
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('nested','Nested','','manual',1,'[]',0,?)`, doc); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportConfig(t.Context(), db.DB()); err == nil {
		t.Fatal("deeply nested endpoint should be rejected before export")
	}
}

func TestPrePolicySelectorConfigurationExportRemainsRestorable(t *testing.T) {
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, q := range []string{
		`INSERT INTO nodes_v2 VALUES('n','Node','manual','manual',1,'["direct"]',0,'{"id":"n","name":"Node","origin":"manual","enabled":true,"chain":[{"type":"direct","direct":{}}]}')`,
		`INSERT INTO outbound_selectors(id,name,node_id,revision) VALUES('s','Manual','n',1)`,
	} {
		if _, err := s.DB().ExecContext(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	data, err := ExportConfig(t.Context(), s.DB())
	if err != nil {
		t.Fatal(err)
	}
	var backup ConfigBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatal(err)
	}
	table := backup.Tables["outbound_selectors"]
	table.Columns = table.Columns[:4]
	for i := range table.Rows {
		table.Rows[i] = table.Rows[i][:4]
	}
	backup.Tables["outbound_selectors"] = table
	data, err = json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(t.Context(), s.DB(), data); err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(t.Context(), s.DB(), data); err != nil {
		t.Fatal(err)
	}
	var policy string
	if err := s.DB().QueryRowContext(t.Context(), `SELECT policy_json FROM outbound_selectors WHERE id='s'`).Scan(&policy); err != nil || policy != "null" {
		t.Fatal(policy, err)
	}
}

func TestConfigBackupRoundTripAndAtomicFailure(t *testing.T) {
	ctx := t.Context()
	source, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, statement := range []string{
		`INSERT INTO android_extra_preferences VALUES ('route_content_custom', '"0.0.0.0/0"', 9223372036854775806)`,
		`INSERT INTO metadata VALUES ('selected_tcp_node_v2', 'test-node')`,
		`INSERT INTO metadata VALUES ('source_runtime_marker', 'do-not-export')`,
		`INSERT INTO nodes_v2 VALUES ('test-node', 'Backup node', 'test', 'manual', 1, '["direct"]', 42, '{"id":"test-node","name":"Backup node","enabled":true,"chain":[{"type":"direct","direct":{}}]}')`,
		`INSERT INTO statistics_kv VALUES ('total_download', 1000, 1)`,
	} {
		if _, err := source.DB().ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	data, err := ExportConfig(ctx, source.DB())
	if err != nil {
		t.Fatal(err)
	}
	target, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := target.DB().ExecContext(ctx, `INSERT INTO metadata VALUES ('target_marker', 'keep')`); err != nil {
		t.Fatal(err)
	}
	if _, err := target.DB().ExecContext(ctx, `INSERT INTO statistics_kv VALUES ('total_download', 700, 1)`); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(ctx, target.DB(), data); err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(ctx, target.DB(), data); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := target.DB().QueryRowContext(ctx, `SELECT name FROM nodes_v2`).Scan(&name); err != nil || name != "Backup node" {
		t.Fatalf("restored node: %s, %v", name, err)
	}
	var timestamp int64
	if err := target.DB().QueryRowContext(ctx, `SELECT updated_at FROM android_extra_preferences`).Scan(&timestamp); err != nil || timestamp != 9223372036854775806 {
		t.Fatalf("integer precision: %d, %v", timestamp, err)
	}
	var total int
	if err := target.DB().QueryRowContext(ctx, `SELECT value_int FROM statistics_kv`).Scan(&total); err != nil || total != 700 {
		t.Fatalf("runtime totals were overwritten: %d, %v", total, err)
	}
	var marker string
	if err := target.DB().QueryRowContext(ctx, `SELECT value FROM metadata WHERE key='target_marker'`).Scan(&marker); err != nil || marker != "keep" {
		t.Fatal("local marker changed", err)
	}
	var backup ConfigBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatal(err)
	}
	bad := backup.Tables["nodes_v2"]
	bad.Rows[0][7] = jsontext.Value(`"not valid JSON"`)
	backup.Tables["nodes_v2"] = bad
	broken, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(ctx, target.DB(), broken); err == nil {
		t.Fatal("invalid backup passed preview validation")
	}
	if err := RestoreConfig(ctx, target.DB(), broken); err == nil {
		t.Fatal("expected SQLite constraint failure")
	}
	if err := target.DB().QueryRowContext(ctx, `SELECT name FROM nodes_v2`).Scan(&name); err != nil || name != "Backup node" {
		t.Fatal("failed restore did not roll back", err)
	}
	if err := target.DB().QueryRowContext(ctx, `SELECT updated_at FROM android_extra_preferences`).Scan(&timestamp); err != nil || timestamp != 9223372036854775806 {
		t.Fatal("earlier tables were not rolled back", err)
	}
}

func TestConfigBackupRejectsIncompleteOrUnknownFormat(t *testing.T) {
	ctx := t.Context()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	data, err := ExportConfig(ctx, store.DB())
	if err != nil {
		t.Fatal(err)
	}
	var backup ConfigBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatal(err)
	}
	backup.Version = 2
	future, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(ctx, store.DB(), future); err == nil {
		t.Fatal("accepted future version")
	}
	backup.Version = 1
	delete(backup.Tables, "nodes_v2")
	partial, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(ctx, store.DB(), partial); err == nil {
		t.Fatal("accepted incomplete backup")
	}
	backup.Tables["nodes_v2"] = ConfigBackupTable{Columns: []string{"id); DROP TABLE nodes_v2; --"}}
	invalid, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(ctx, store.DB(), invalid); err == nil {
		t.Fatal("accepted untrusted columns")
	}
}
