package backup

import (
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestConfigurationBackupsRemoveAuthenticationMaterial(t *testing.T) {
	const shortID = "ca70b15e20261031"
	const publicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	for _, tc := range []struct {
		name, insert, selectRow, document, private string
		public                                     []string
	}{
		{"node", `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('reality','Reality','','manual',1,'["reality"]',1,?)`, `SELECT enabled,data_json FROM nodes_v2 WHERE id='reality'`, `{"id":"reality","name":"Reality","origin":"manual","enabled":true,"chain":[{"type":"reality","reality":{"server_name":"example.org","public_key":"` + publicKey + `","short_id":"` + shortID + `"}}]}`, shortID, []string{publicKey, "example.org"}},
		{"inbound", `INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,updated_at,data_json) VALUES('reality','Reality',1,'tcp_udp','none','["reality"]',1,?)`, `SELECT enabled,data_json FROM inbounds_v2 WHERE id='reality'`, `{"id":"reality","name":"Reality","enabled":true,"network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:1080"}},"transports":[{"type":"reality","reality":{"shortIds":["` + shortID + `"],"serverNames":["example.org"],"dest":"example.org:443","publicKey":"` + publicKey + `"}}],"protocol":{"type":"none","none":{}}}`, shortID, []string{publicKey, "example.org"}},
		{"username-only node", `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES('endpoint','Public endpoint','','manual',1,'["http"]',1,?)`, `SELECT enabled,data_json FROM nodes_v2 WHERE id='endpoint'`, `{"id":"endpoint","name":"Public endpoint","origin":"manual","enabled":true,"chain":[{"type":"http","http":{"user":"username-only-marker","password":""}}]}`, "username-only-marker", []string{"Public endpoint"}},
		{"username-only inbound", `INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,updated_at,data_json) VALUES('endpoint','Public endpoint',1,'tcp_udp','http','[]',1,?)`, `SELECT enabled,data_json FROM inbounds_v2 WHERE id='endpoint'`, `{"id":"endpoint","name":"Public endpoint","enabled":true,"network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:1080"}},"transports":[],"protocol":{"type":"http","http":{"username":"username-only-marker","password":""}}}`, "username-only-marker", []string{"Public endpoint", "127.0.0.1:1080"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var object []byte
			b, _ := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					object, _ = io.ReadAll(r.Body)
					return
				}
				_, _ = w.Write(object)
			})
			db, err := testfixture.OpenState(t.Context(), paths.PathGenerator.State(b.dir))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.DB().ExecContext(t.Context(), tc.insert, tc.document); err != nil {
				t.Fatal(err)
			}
			checkRedacted := func(reader *sql.DB) {
				t.Helper()
				var enabled int
				var document string
				if err := reader.QueryRowContext(t.Context(), tc.selectRow).Scan(&enabled, &document); err != nil {
					t.Fatal(err)
				}
				if enabled != 0 || !strings.Contains(document, `"enabled":false`) || strings.Contains(document, tc.private) {
					t.Fatal("redacted endpoint must be disabled without authentication material")
				}
				for _, value := range tc.public {
					if !strings.Contains(document, value) {
						t.Fatal("redaction changed public endpoint configuration")
					}
				}
			}
			data, err := storagesqlite.ExportConfig(t.Context(), db.DB())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(tc.private)) {
				t.Fatal("Authentication material entered plaintext JSON export")
			}
			target, err := testfixture.OpenState(t.Context(), filepath.Join(t.TempDir(), "restored.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if err := storagesqlite.RestoreConfig(t.Context(), target.DB(), data); err != nil {
				t.Fatal(err)
			}
			checkRedacted(target.DB())
			if err := b.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
			if len(object) == 0 || bytes.Contains(object, []byte(tc.private)) {
				t.Fatal("Authentication material entered plaintext S3 snapshot")
			}
			path := filepath.Join(t.TempDir(), "snapshot.db")
			if err := os.WriteFile(path, object, 0o600); err != nil {
				t.Fatal(err)
			}
			snapshot, err := testfixture.OpenState(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer snapshot.Close()
			checkRedacted(snapshot.DB())
			var enabled int
			var live string
			if err := db.DB().QueryRowContext(t.Context(), tc.selectRow).Scan(&enabled, &live); err != nil || enabled != 1 || live != tc.document {
				t.Fatal("configuration backup changed the live endpoint", err)
			}
		})
	}
}
