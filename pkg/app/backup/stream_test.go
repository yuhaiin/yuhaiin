package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	"go.uber.org/goleak"
)

func TestConfigurationS3SnapshotDoesNotContainPrivateRuntimeMaterial(t *testing.T) {
	var object []byte
	b, store := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			object, _ = io.ReadAll(r.Body)
			return
		}
		_, _ = w.Write(object)
	})
	config, err := store.Runtime(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	config.S3.AccessKey, config.S3.SecretKey = "s3-access-key-marker", "s3-secret-key-marker"
	if err := store.Save(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		`INSERT INTO managed_certificates(id,revision,config_json,status_json) VALUES('cert',1,'{}','{}')`,
		`INSERT INTO managed_certificate_material VALUES('cert','certificate','site-private-key-marker')`,
		`INSERT INTO certificate_acme_accounts VALUES('https://ca.invalid','mail@example.com','acme-private-key-marker','')`,
		`INSERT INTO certificate_dns_providers VALUES('provider',1,'{}','dns-provider-token-marker')`,
		`INSERT INTO gateway_ca VALUES(1,1,'certificate','gateway-ca-private-key-marker')`,
		`INSERT INTO metadata(key,value) VALUES('private_runtime_marker','private-runtime-marker')`,
		`INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('wg','WireGuard','','manual',1,'["wireguard"]',0,'{"id":"wg","name":"WireGuard","origin":"manual","enabled":true,"chain":[{"type":"wireguard","wireguard":{"secretKey":"wire-private-marker","peers":[{"preSharedKey":"wire-preshared-marker"}]}}]}')`,
		`INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,updated_at,data_json) VALUES('inbound','Inbound',1,'tcp_udp','http','[]',0,'{"id":"inbound","name":"Inbound","enabled":true,"network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:1080"}},"transports":[],"protocol":{"type":"http","http":{"username":"alice","password":"inbound-password-marker"}}}')`,
		`INSERT INTO nodes(hash,group_name,name,origin,selected_tcp,search_text,updated_at,data_json) VALUES('legacy','fixture','Legacy',1,1,'legacy-search-secret-marker',1,'{"name":"Legacy","wireguard":{"secretKey":"legacy-wire-key-marker"}}')`,
		`INSERT INTO nodes_fts(rowid,name,group_name,search_text) SELECT id,name,group_name,search_text FROM nodes WHERE hash='legacy'`,
		`INSERT INTO inbounds(name,enabled,inbound_type,listen_host,updated_at,data_json) VALUES('legacy-inbound',1,'http','127.0.0.1:1080',1,'{"name":"legacy-inbound","http":{"password":"legacy-password-marker"}}')`,
		`INSERT INTO subscriptions(name,updated_at,data_json) VALUES('upstream',1,'{"name":"upstream","url":"https://example.com/subscription-path-marker","type":"reserve"}')`,
		`INSERT INTO publishes(name,updated_at,data_json) VALUES('publication',1,'{"name":"publication","password":"publish-password-marker","path":"publish-path-marker","points":["wg"],"address":"example.com","insecure":false}')`,
		`INSERT INTO gateway_configuration(id,revision,data_json) VALUES(1,1,'{"version":2,"revision":1,"gateways":[{"id":"g1","name":"Protected","enabled":true,"revision":1,"policies":[{"id":"policy","name":"auth","enabled":true,"match":{"all":[{"field":"header","operator":"exact","key":"Authorization","values":["Bearer condition-secret-marker"]},{"not":{"field":"query","operator":"exact","key":"token","values":["query-secret-marker"]}}]},"action":{"type":"forward","rewrite":{"query":"token=rewrite-query-secret-marker","headers":{"Authorization":["Bearer rewrite-secret-marker"]}},"responseHeaders":{"Set-Cookie":["session=response-secret-marker"]}}}],"backendPools":[],"filters":[],"fallback":{"type":"block","rewrite":{}}},{"id":"g2","name":"Unchanged","enabled":true,"revision":1,"policies":[],"backendPools":[],"filters":[],"fallback":{"type":"block","rewrite":{}}}]}')`,
	} {
		if _, err := db.DB().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	jsonExport, err := storagesqlite.ExportConfig(t.Context(), db.DB())
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"condition-secret-marker", "query-secret-marker", "rewrite-secret-marker", "response-secret-marker"} {
		if bytes.Contains(jsonExport, []byte(marker)) {
			t.Fatalf("JSON configuration export contains %s", marker)
		}
	}
	importTarget, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "import.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer importTarget.Close()
	if err := storagesqlite.RestoreConfig(t.Context(), importTarget.DB(), jsonExport); err != nil {
		t.Fatal("cannot import redacted JSON configuration", err)
	}
	jsonGateway, err := plainstore.NewGatewayStore(importTarget.DB()).Load(t.Context())
	if err != nil || len(jsonGateway.Gateways) != 2 || jsonGateway.Gateways[0].Enabled || !jsonGateway.Gateways[1].Enabled {
		t.Fatal("unsafe gateway state after JSON import", jsonGateway, err)
	}
	if len(jsonGateway.Rules) != 1 || jsonGateway.Rules[0].Enabled {
		t.Fatal("redacted JSON gateway rule remained enabled", jsonGateway.Rules)
	}
	if _, err := gateway.CompilePolicy(jsonGateway.Rules, jsonGateway.Gateways[0].Default); err != nil {
		t.Fatal("redacted JSON gateway policy cannot be compiled", err)
	}
	manager, err := gateway.NewManager(t.Context(), plainstore.NewGatewayStore(importTarget.DB()), nil, nil)
	if err != nil {
		t.Fatal("cannot start imported Gateway configuration", err)
	}
	defer manager.Close()
	if status := manager.Status(); status.StartupError != "" {
		t.Fatal("cannot activate imported Gateway configuration", status.StartupError)
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !manager.InterceptGateway(netapi.WithContext(t.Context()), &netapi.StreamMeta{Src: server}, "g1") {
		t.Fatal("routing through a redacted Gateway fell back to ordinary forwarding")
	}
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("redacted Gateway did not reject selected traffic: %v", err)
	}
	// A client predating the safety marker can save other settings while the
	// Gateway is disabled; it must not accidentally remove the rejection guard.
	draft := manager.Config()
	draft.Gateways[0].RejectWhenDisabled = false
	saved, err := manager.Save(t.Context(), draft)
	if err != nil || !saved.Gateways[0].RejectWhenDisabled {
		t.Fatal("saving a disabled imported Gateway lost its safety guard", saved, err)
	}
	reloaded, err := plainstore.NewGatewayStore(importTarget.DB()).Load(t.Context())
	if err != nil || !reloaded.Gateways[0].RejectWhenDisabled {
		t.Fatal("disabled Gateway safety guard was not persisted", reloaded, err)
	}
	saved.Gateways[0].Enabled = true
	saved, err = manager.Save(t.Context(), saved)
	if err != nil || !saved.Gateways[0].Enabled || saved.Gateways[0].RejectWhenDisabled {
		t.Fatal("explicitly enabling the reviewed Gateway did not release its guard", saved, err)
	}
	if err := b.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"site-private-key-marker", "acme-private-key-marker", "dns-provider-token-marker", "gateway-ca-private-key-marker", "private-runtime-marker", "s3-access-key-marker", "s3-secret-key-marker", "wire-private-marker", "wire-preshared-marker", "inbound-password-marker", "legacy-search-secret-marker", "legacy-wire-key-marker", "legacy-password-marker", "subscription-path-marker", "publish-password-marker", "publish-path-marker", "condition-secret-marker", "query-secret-marker", "rewrite-secret-marker", "response-secret-marker"} {
		if bytes.Contains(object, []byte(marker)) {
			t.Errorf("configuration S3 object contains %s", marker)
		}
	}
	var count int
	if err := db.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM managed_certificate_material`).Scan(&count); err != nil || count != 1 {
		t.Fatal("sanitizing the export modified the live certificate", count, err)
	}
	var liveEnabled int
	if err := db.DB().QueryRowContext(t.Context(), `SELECT enabled FROM nodes_v2 WHERE id='wg'`).Scan(&liveEnabled); err != nil || liveEnabled != 1 {
		t.Fatal("sanitizing the export modified the live node", liveEnabled, err)
	}
	if err := db.DB().QueryRowContext(t.Context(), `SELECT enabled FROM inbounds_v2 WHERE id='inbound'`).Scan(&liveEnabled); err != nil || liveEnabled != 1 {
		t.Fatal("sanitizing the export modified the live inbound", liveEnabled, err)
	}
	if err := db.DB().QueryRowContext(t.Context(), `SELECT selected_tcp FROM nodes WHERE hash='legacy'`).Scan(&liveEnabled); err != nil || liveEnabled != 1 {
		t.Fatal("sanitizing the export changed the live legacy selection", liveEnabled, err)
	}
	if err := db.DB().QueryRowContext(t.Context(), `SELECT json_extract(data_json,'$.gateways[0].enabled') FROM gateway_configuration WHERE id=1`).Scan(&liveEnabled); err != nil || liveEnabled != 1 {
		t.Fatal("sanitizing the export changed the live gateway", liveEnabled, err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.db")
	if err := os.WriteFile(path, object, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := storagesqlite.InspectBackupSnapshot(t.Context(), path, "configuration"); err != nil {
		t.Fatal("sanitized snapshot cannot be inspected", err)
	}
	snapshot, err := storagesqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	configuration, err := plainstore.NewGatewayStore(snapshot.DB()).Load(t.Context())
	if err != nil {
		t.Fatal("redacted gateway configuration is unreadable", err)
	}
	if len(configuration.Gateways) != 2 || configuration.Gateways[0].Enabled || !configuration.Gateways[1].Enabled || len(configuration.Rules) != 1 || configuration.Rules[0].Enabled {
		t.Fatalf("unsafe or unrelated gateway activation changed: %+v", configuration)
	}
	if _, err := gateway.CompilePolicy(configuration.Rules, configuration.Gateways[0].Default); err != nil {
		t.Fatal("redacted gateway policy cannot be compiled", err)
	}
	if err := snapshot.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM subscriptions`).Scan(&count); err != nil || count != 0 {
		t.Fatal("S3 snapshot retained subscription URL", count, err)
	}
	var publication string
	if err := snapshot.DB().QueryRowContext(t.Context(), `SELECT data_json FROM publishes WHERE name='publication'`).Scan(&publication); err != nil || bytes.Contains([]byte(publication), []byte(`"wg"`)) {
		t.Fatal("S3 snapshot retained publish targets", publication, err)
	}
	resolved, err := plainstore.NewSubscriptionStore(snapshot.DB()).ResolvePublish(t.Context(), "publication", "", "")
	if err != nil || len(resolved.Points) != 0 {
		t.Fatal("redacted publication exposes nodes with an empty password", resolved, err)
	}
	var exportedEnabled int
	if err := snapshot.DB().QueryRowContext(t.Context(), `SELECT enabled FROM nodes_v2 WHERE id='wg'`).Scan(&exportedEnabled); err != nil || exportedEnabled != 0 {
		t.Fatal("redacted node remained enabled in S3 snapshot", exportedEnabled, err)
	}
	if err := snapshot.DB().QueryRowContext(t.Context(), `SELECT enabled FROM inbounds_v2 WHERE id='inbound'`).Scan(&exportedEnabled); err != nil || exportedEnabled != 0 {
		t.Fatal("redacted inbound remained enabled in S3 snapshot", exportedEnabled, err)
	}
	if err := snapshot.DB().QueryRowContext(t.Context(), `SELECT selected_tcp FROM nodes WHERE hash='legacy'`).Scan(&exportedEnabled); err != nil || exportedEnabled != 0 {
		t.Fatal("redacted legacy node remained selected", exportedEnabled, err)
	}
	if err := snapshot.DB().QueryRowContext(t.Context(), `SELECT enabled FROM inbounds WHERE name='legacy-inbound'`).Scan(&exportedEnabled); err != nil || exportedEnabled != 0 {
		t.Fatal("redacted legacy inbound remained enabled", exportedEnabled, err)
	}
}

func TestConfigurationS3SnapshotRejectsUnknownVirtualTables(t *testing.T) {
	var calls atomic.Int32
	b, _ := streamingBackup(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB().ExecContext(t.Context(), `CREATE VIRTUAL TABLE unknown_private_index USING fts5(value)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO unknown_private_index(value) VALUES('private index content')`); err != nil {
		t.Fatal(err)
	}
	if err := b.Run(t.Context()); err == nil {
		t.Fatal("an unknown virtual index was uploaded without a safe sanitizer")
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe configuration snapshot reached S3")
	}
}

func TestConfigurationS3SnapshotRejectsUnknownTables(t *testing.T) {
	var calls atomic.Int32
	b, _ := streamingBackup(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB().ExecContext(t.Context(), `CREATE TABLE future_private_state (value TEXT NOT NULL); INSERT INTO future_private_state VALUES('future-private-table-marker')`); err != nil {
		t.Fatal(err)
	}
	if err := b.Run(t.Context()); err == nil {
		t.Fatal("unclassified table was accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("unclassified configuration snapshot reached S3")
	}
}

func TestConfigurationS3SnapshotRejectsUnknownGatewayFields(t *testing.T) {
	var calls atomic.Int32
	b, _ := streamingBackup(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO gateway_configuration(id,revision,data_json) VALUES(1,1,'{"version":2,"revision":1,"gateways":[],"futureCredentials":"sensitive-value"}')`); err != nil {
		t.Fatal(err)
	}
	if err := b.Run(t.Context()); err == nil {
		t.Fatal("snapshot accepted unknown gateway data that may contain credentials")
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe gateway snapshot reached S3")
	}
}

func TestConfigurationS3SnapshotRejectsUnknownEndpointFields(t *testing.T) {
	for _, tc := range []struct {
		name, query, document string
	}{
		{"node", `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('n','Node','','manual',1,'[]',0,?)`, `{"id":"n","name":"Node","enabled":true,"chain":[{"type":"ssh","ssh":{"user":"a","host_key":"public","futureVerifier":"sensitive-marker"}}]}`},
		{"unknown sibling after cleared aliases", `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('n','Node','','manual',1,'[]',0,?)`, `{"id":"n","name":"Node","enabled":true,"chain":[{"type":"wireguard","wireguard":{"Private_Key":"sensitive-marker","Pre_Shared_Key":"sensitive-marker","futureVerifier":"sensitive-marker"}}]}`},
		{"inbound", `INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,updated_at,data_json) VALUES('i','Inbound',1,'tcp','http','[]',0,?)`, `{"id":"i","name":"Inbound","enabled":true,"protocol":{"type":"http","http":{"username":"a","futureVerifier":"sensitive-marker"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			b, _ := streamingBackup(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
			db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.DB().ExecContext(t.Context(), tc.query, tc.document); err != nil {
				t.Fatal(err)
			}
			if err := b.Run(t.Context()); err == nil || strings.Contains(err.Error(), "sensitive-marker") {
				t.Fatal("snapshot must reject unknown fields without disclosing their values")
			}
			if calls.Load() != 0 {
				t.Fatal("unsafe endpoint snapshot reached S3")
			}
		})
	}
}

func TestConfigurationBackupsOmitRouteRefreshErrors(t *testing.T) {
	var object []byte
	var uploads atomic.Int32
	b, _ := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			object, _ = io.ReadAll(r.Body)
			uploads.Add(1)
			return
		}
		_, _ = w.Write(object)
	})
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		`INSERT INTO route_lists(name,kind,updated_at,data_json) VALUES('legacy','remote',1,'{}')`,
		`INSERT INTO route_list_refresh(name,refresh_interval,last_refresh_time,last_error) VALUES('legacy',3600,42,'legacy-secret-marker')`,
		`INSERT INTO route_lists_v2(id,name,list_type,source_type,updated_at,data_json) VALUES('list','List','host','remote',1,'{"id":"list","name":"List","type":"host","source":{"type":"remote","remote":{"urls":["https://public.example/list"]}},"errorMsgs":["https://private.example/old-token-marker: failed"]}')`,
		`INSERT INTO settings_kv(section,key,value_json,updated_at) VALUES('route_extra','refresh_config','{"revision":3,"refresh_interval":3600,"last_refresh_time":42,"error":"refresh-secret-marker","host_index_disk":true}',1)`,
		`INSERT INTO settings_kv(section,key,value_json,updated_at) VALUES('route_extra','maxminddb_geoip','{"download_url":"https://public.example/geoip","error":"geoip-secret-marker"}',1)`,
		`INSERT INTO settings_kv(section,key,value_json,updated_at) VALUES('other','settings','{"error":"keep-unrelated-value"}',1)`,
	} {
		if _, err := db.DB().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	jsonExport, err := storagesqlite.ExportConfig(t.Context(), db.DB())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := b.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if uploads.Load() != 1 {
		t.Fatal("unchanged sanitized configuration was uploaded repeatedly")
	}
	for _, data := range [][]byte{jsonExport, object} {
		for _, marker := range []string{"legacy-secret-marker", "old-token-marker", "refresh-secret-marker", "geoip-secret-marker"} {
			if bytes.Contains(data, []byte(marker)) {
				t.Fatal("configuration backup retained a route refresh error")
			}
		}
	}
	jsonTarget, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "json.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer jsonTarget.Close()
	if err := storagesqlite.RestoreConfig(t.Context(), jsonTarget.DB(), jsonExport); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "s3.db")
	if err := os.WriteFile(path, object, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := storagesqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	for i, restored := range []*storagesqlite.Store{jsonTarget, snapshot} {
		var list, refresh, geo, unrelated, lastError string
		var interval, lastRefresh int
		if err := restored.DB().QueryRowContext(t.Context(), `SELECT data_json FROM route_lists_v2 WHERE id='list'`).Scan(&list); err != nil {
			t.Fatal(err)
		}
		if err := restored.DB().QueryRowContext(t.Context(), `SELECT value_json FROM settings_kv WHERE section='route_extra' AND key='refresh_config'`).Scan(&refresh); err != nil {
			t.Fatal(err)
		}
		if err := restored.DB().QueryRowContext(t.Context(), `SELECT value_json FROM settings_kv WHERE section='route_extra' AND key='maxminddb_geoip'`).Scan(&geo); err != nil {
			t.Fatal(err)
		}
		if err := restored.DB().QueryRowContext(t.Context(), `SELECT value_json FROM settings_kv WHERE section='other' AND key='settings'`).Scan(&unrelated); err != nil {
			t.Fatal(err)
		}
		if err := restored.DB().QueryRowContext(t.Context(), `SELECT refresh_interval,last_refresh_time,last_error FROM route_list_refresh WHERE name='legacy'`).Scan(&interval, &lastRefresh, &lastError); err != nil {
			t.Fatal(err)
		}
		wantLastRefresh := 42
		if i == 1 {
			wantLastRefresh = 0 // S3 snapshots already reset runtime refresh time.
		}
		if !strings.Contains(list, "https://public.example/list") || !strings.Contains(refresh, `"refresh_interval":3600`) || !strings.Contains(geo, "https://public.example/geoip") || !strings.Contains(unrelated, "keep-unrelated-value") || interval != 3600 || lastRefresh != wantLastRefresh || lastError != "" {
			t.Fatalf("route settings changed: list=%t refresh=%t geo=%t unrelated=%t interval=%d lastRefresh=%d cleared=%t", strings.Contains(list, "https://public.example/list"), strings.Contains(refresh, `"refresh_interval":3600`), strings.Contains(geo, "https://public.example/geoip"), strings.Contains(unrelated, "keep-unrelated-value"), interval, lastRefresh, lastError == "")
		}
	}
	var live string
	if err := db.DB().QueryRowContext(t.Context(), `SELECT last_error FROM route_list_refresh WHERE name='legacy'`).Scan(&live); err != nil || live != "legacy-secret-marker" {
		t.Fatal("backup changed live route refresh status", err)
	}
	for _, query := range []string{
		`SELECT instr(data_json,'old-token-marker') FROM route_lists_v2 WHERE id='list'`,
		`SELECT instr(value_json,'refresh-secret-marker') FROM settings_kv WHERE section='route_extra' AND key='refresh_config'`,
		`SELECT instr(value_json,'geoip-secret-marker') FROM settings_kv WHERE section='route_extra' AND key='maxminddb_geoip'`,
	} {
		var position int
		if err := db.DB().QueryRowContext(t.Context(), query).Scan(&position); err != nil || position == 0 {
			t.Fatal("backup changed live route refresh status", err)
		}
	}
}

func TestConfigurationBackupsRejectAmbiguousRouteRefreshErrors(t *testing.T) {
	var calls atomic.Int32
	b, _ := streamingBackup(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO route_lists_v2(id,name,list_type,source_type,updated_at,data_json) VALUES('list','List','host','remote',1,'{"errorMsgs":["first-secret"],"errorMsgs":["second-secret"]}')`); err != nil {
		t.Fatal(err)
	}
	if data, err := storagesqlite.ExportConfig(t.Context(), db.DB()); err == nil || len(data) != 0 {
		t.Fatal("ambiguous route errors were exported")
	}
	if err := b.Run(t.Context()); err == nil || calls.Load() != 0 {
		t.Fatal("ambiguous route errors reached S3")
	}
}

func TestConfigurationS3SnapshotRedactsHTTPMockPayloads(t *testing.T) {
	const payload = "c2VjcmV0LW1vY2stbWFya2Vy"
	var object []byte
	b, _ := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			object, _ = io.ReadAll(r.Body)
			return
		}
		_, _ = w.Write(object)
	})
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	node := `{"id":"mock-node","name":"Mock","enabled":true,"chain":[{"type":"http_mock","http_mock":{"data":"` + payload + `"}}]}`
	inbound := `{"id":"mock-inbound","name":"Mock","enabled":true,"transports":[{"type":"http_mock","http_mock":{"dataBase64":"` + payload + `"}}]}`
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('mock-node','Mock','','manual',1,'[]',0,?)`, node); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,updated_at,data_json) VALUES('mock-inbound','Mock',1,'tcp','http','[]',0,?)`, inbound); err != nil {
		t.Fatal(err)
	}
	if err := b.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(object, []byte(payload)) {
		t.Fatal("S3 snapshot retained an HTTP Mock payload")
	}
	path := filepath.Join(t.TempDir(), "s3-snapshot.db")
	if err := os.WriteFile(path, object, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := storagesqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	for _, table := range []string{"nodes_v2", "inbounds_v2"} {
		var enabled int
		var data string
		if err := snapshot.DB().QueryRowContext(t.Context(), "SELECT enabled,data_json FROM "+table).Scan(&enabled, &data); err != nil || enabled != 0 || !strings.Contains(data, `"enabled":false`) {
			t.Fatal("redacted endpoint remained enabled", table, err)
		}
	}
	for table, original := range map[string]string{"nodes_v2": node, "inbounds_v2": inbound} {
		var live string
		if err := db.DB().QueryRowContext(t.Context(), "SELECT data_json FROM "+table).Scan(&live); err != nil || live != original {
			t.Fatal("snapshot changed live configuration", table, err)
		}
	}
}

func TestConfigurationS3SnapshotRedactsShadowsocksRParameters(t *testing.T) {
	var object []byte
	b, _ := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			object, _ = io.ReadAll(r.Body)
			return
		}
		_, _ = w.Write(object)
	})
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	doc := `{"id":"ssr","name":"SSR","origin":"manual","enabled":true,"chain":[{"type":"shadowsocksr","shadowsocksr":{"protocol":"auth_chain_a","protoparam":"42:ssr-protocol-secret-marker","obfs":"http_simple","obfsparam":"vpn.example#Authorization: ssr-header-secret-marker"}}]}`
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('ssr','SSR','','manual',1,'["shadowsocksr"]',0,?)`, doc); err != nil {
		t.Fatal(err)
	}
	if err := b.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"ssr-protocol-secret-marker", "ssr-header-secret-marker"} {
		if bytes.Contains(object, []byte(marker)) {
			t.Fatal("S3 snapshot retained a ShadowsocksR credential")
		}
	}
	path := filepath.Join(t.TempDir(), "s3-snapshot.db")
	if err := os.WriteFile(path, object, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := storagesqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var enabled int
	var sanitized string
	if err := snapshot.DB().QueryRowContext(t.Context(), `SELECT enabled,data_json FROM nodes_v2 WHERE id='ssr'`).Scan(&enabled, &sanitized); err != nil || enabled != 0 || !strings.Contains(sanitized, `"enabled":false`) {
		t.Fatal("redacted ShadowsocksR node was not disabled", err)
	}
	var source string
	if err := db.DB().QueryRowContext(t.Context(), `SELECT data_json FROM nodes_v2 WHERE id='ssr'`).Scan(&source); err != nil || source != doc {
		t.Fatal("snapshot changed the live ShadowsocksR node", err)
	}
}

func TestConfigurationS3SnapshotRedactsGatewayURLCredentials(t *testing.T) {
	var object []byte
	var uploads atomic.Int32
	b, _ := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			object, _ = io.ReadAll(r.Body)
			uploads.Add(1)
			return
		}
		_, _ = w.Write(object)
	})
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	doc := `{"version":2,"revision":1,"gateways":[{"id":"g","name":"Gateway","enabled":true,"revision":1,"policies":[],"backendPools":[],"filters":[{"id":"filter","gatewayId":"g","enabled":true,"url":"https://example.org/list?token=s3-filter-secret-marker","text":""}],"fallback":{"type":"redirect","status":302,"location":"?token=s3-redirect-secret-marker","rewrite":{}}}]}`
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO gateway_configuration(id,revision,data_json) VALUES(1,1,?)`, doc); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := b.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if uploads.Load() != 1 {
		t.Fatalf("unchanged sanitized Gateway uploaded %d times", uploads.Load())
	}
	for _, marker := range []string{"s3-filter-secret-marker", "s3-redirect-secret-marker"} {
		if bytes.Contains(object, []byte(marker)) {
			t.Fatalf("S3 object contains %s", marker)
		}
	}
	path := filepath.Join(t.TempDir(), "s3-snapshot.db")
	if err := os.WriteFile(path, object, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := storagesqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	config, err := plainstore.NewGatewayStore(snapshot.DB()).Load(t.Context())
	if err != nil || len(config.Gateways) != 1 || config.Gateways[0].Enabled || config.Gateways[0].Default.Location != "/" {
		t.Fatal("redacted relative redirect is invalid", config, err)
	}
	if _, err := gateway.CompilePolicy(config.Rules, config.Gateways[0].Default); err != nil {
		t.Fatal("redacted fallback cannot be compiled", err)
	}
	var source string
	if err := db.DB().QueryRowContext(t.Context(), `SELECT data_json FROM gateway_configuration WHERE id=1`).Scan(&source); err != nil || source != doc {
		t.Fatal("snapshot changed live Gateway configuration", err)
	}
}

func streamingBackup(t *testing.T, handler http.HandlerFunc) (*Backup, *backupstore.Store) {
	t.Helper()
	directory := t.TempDir()
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(directory))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := backupstore.New(db.DB())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	if err := store.Save(t.Context(), contractbackup.Option{InstanceName: "fixture", S3: contractbackup.S3{Enabled: true, EndpointURL: server.URL, Bucket: "backups", AccessKey: "access", SecretKey: "secret"}}); err != nil {
		t.Fatal(err)
	}
	b := New(store, directory, nil, direct.Default)
	t.Cleanup(func() { _ = b.Close() })
	return b, store
}

func TestBackupDownloadVerificationAndSkipUnchanged(t *testing.T) {
	var mu sync.Mutex
	var data []byte
	var corrupt atomic.Bool
	var uploads atomic.Int32
	b, store := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut {
			data, _ = io.ReadAll(r.Body)
			uploads.Add(1)
			return
		}
		if corrupt.Load() {
			_, _ = w.Write([]byte("corrupt"))
			return
		}
		_, _ = w.Write(data)
	})
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(b.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('node','Node','','manual',1,'["ssh"]',1,'{"id":"node","name":"Node","enabled":true,"origin":"manual","chain":[{"type":"simple","simple":{"host":"host.example"}},{"type":"ssh","ssh":{"user":"admin","password":"private","hostKey":"public"}}]}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO publishes(name,updated_at,data_json) VALUES('publication',1,'{"name":"publication","password":"private","path":"private-path","points":["node"],"address":"example.org","insecure":false}')`); err != nil {
		t.Fatal(err)
	}
	corrupt.Store(true)
	if err := b.Run(t.Context()); err == nil {
		t.Fatal("corrupt downloaded verification was accepted")
	}
	opt, err := store.Get(t.Context())
	if err != nil || opt.LastBackupHash != "" {
		t.Fatal("unverified upload marked successful")
	}
	corrupt.Store(false)
	for range 4 {
		if err := b.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	opt, err = store.Get(t.Context())
	if err != nil || opt.LastBackupHash == "" {
		t.Fatal("verified backup hash not recorded")
	}
	if err := b.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if uploads.Load() != 2 {
		t.Fatalf("unchanged backup uploaded again: %d", uploads.Load())
	}
	leftovers, err := filepath.Glob(filepath.Join(b.dir, ".state-backup-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("snapshot leaked: %v, %v", leftovers, err)
	}
}

func TestBackupSettingsAreNotOverwrittenByCompletedUpload(t *testing.T) {
	uploaded := make(chan struct{})
	release := make(chan struct{})
	var data []byte
	b, store := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			data, _ = io.ReadAll(r.Body)
			return
		}
		close(uploaded)
		<-release
		_, _ = w.Write(data)
	})
	result := make(chan error, 1)
	go func() { result <- b.Run(t.Context()) }()
	select {
	case <-uploaded:
	case err := <-result:
		t.Fatal("backup returned before readback", err)
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not finish")
	}
	opt, err := b.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	opt.InstanceName = "changed"
	if _, err := b.Save(t.Context(), opt); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(t.Context())
	if err != nil || got.InstanceName != "changed" || got.LastBackupHash != "" {
		t.Fatalf("concurrent settings overwritten: %+v, %v", got, err)
	}
}

func TestBackupCloseCancelsManualTransfer(t *testing.T) {
	started := make(chan struct{}, 1)
	b, _ := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-t.Context().Done():
		}
	})
	result := make(chan error, 1)
	go func() { result <- b.Run(t.Context()) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("backup did not start")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("close did not cancel manual work: %v", err)
	}
	if err := b.Run(t.Context()); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed backup accepted work: %v", err)
	}
}

func TestBackupRepeatedScheduleChangesDoNotLeak(t *testing.T) {
	dir := t.TempDir()
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	store := backupstore.New(db.DB())
	b := New(store, dir, nil, direct.Default)
	for i := range 100 {
		if _, err := b.Save(t.Context(), contractbackup.Option{InstanceName: "fixture", Interval: uint64(i % 2), S3: contractbackup.S3{Enabled: true}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Save(t.Context(), contractbackup.Option{Interval: ^uint64(0)}); err == nil {
		t.Fatal("overflowing interval accepted")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBackupSnapshotIsPrivateAndCancelled(t *testing.T) {
	b, _ := streamingBackup(t, func(http.ResponseWriter, *http.Request) {})
	snapshot, err := b.snapshotStateDB(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	path := snapshot.Name()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("snapshot permissions: %v, %v", info, err)
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || dir.Mode().Perm()&0o077 != 0 {
		t.Fatal("snapshot directory is public")
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("closed snapshot remains")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := b.snapshotStateDB(ctx); err == nil {
		t.Fatal("cancelled SQLite snapshot accepted")
	}
	leftovers, _ := filepath.Glob(filepath.Join(b.dir, ".state-backup-*"))
	if len(leftovers) != 0 {
		t.Fatal("cancelled snapshot leaked")
	}
}
