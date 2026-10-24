package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type secretTestNodeController struct {
	httpapi.NodeController
	nodes *plainstore.NodeStore
}

func (c secretTestNodeController) Save(ctx context.Context, node contractnode.Node) (contractnode.Node, error) {
	if err := c.nodes.Save(ctx, node, 0); err != nil {
		return contractnode.Node{}, err
	}
	return c.nodes.Get(ctx, node.ID)
}

func TestConfigurationSecretsDefaultMaskPreservationAndExplicitRetrieval(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	reader := testUser(t, s, "reader", ReadOnly)
	full, err := s.IssueToken(t.Context(), principal(admin), admin.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.IssueToken(t.Context(), principal(reader), reader.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := s.IssueToken(t.Context(), principal(admin), admin.ID, []Permission{NodesRead, NodesWrite}, 0)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	nodes := plainstore.NewNodeStore(db.DB())
	input := contractnode.Node{ID: "private", Name: "Private node", Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{{Type: "shadowsocks", Shadowsocks: &contractnode.Shadowsocks{Method: "aes-128-gcm", Password: "reusable-upstream-proof"}}}}
	if err := nodes.Save(t.Context(), input, 0); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	httpapi.RegisterV2(func(pattern string, h func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = h(w, r) })
	}, httpapi.V2Services{Nodes: nodes, Node: secretTestNodeController{nodes: nodes}})
	server := &Server{Store: s, Permissions: httpapi.ManagementPermissions()}
	gate := server.Wrap(mux)
	request := func(path, proof string, body any, reveal bool) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/api/v2/rpc/"+path, bytes.NewReader(encoded))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+proof)
		if reveal {
			r.Header.Set(secretAccessHeader, "reveal")
		}
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w
	}
	for _, proof := range []string{read.Secret, full.Secret} {
		w := request("node.get", proof, map[string]string{"id": "private"}, false)
		if w.Code != 200 || strings.Contains(w.Body.String(), input.Chain[0].Shadowsocks.Password) || !strings.Contains(w.Body.String(), secret.Preserved) {
			t.Fatalf("default configuration read exposed a proof: %d %s", w.Code, w.Body.String())
		}
	}
	masked, err := secret.Redact(input)
	if err != nil {
		t.Fatal(err)
	}
	masked.Name = "Renamed without secret access"
	w := request("node.put", edit.Secret, masked, false)
	if w.Code != 200 {
		t.Fatalf("metadata-only save failed: %d %s", w.Code, w.Body.String())
	}
	stored, err := nodes.Get(t.Context(), input.ID)
	if err != nil || stored.Name != masked.Name || stored.Chain[0].Shadowsocks.Password != input.Chain[0].Shadowsocks.Password {
		t.Fatal("masked save changed the stored secret", err)
	}
	masked.Chain[0].Shadowsocks.Password = "unauthorized-replacement"
	w = request("node.put", edit.Secret, masked, false)
	if w.Code != 403 {
		t.Fatalf("node writer changed an inline proof without secret authority: %d", w.Code)
	}
	masked.ID = "another-resource"
	masked.Chain[0].Shadowsocks.Password = secret.Preserved
	if w = request("node.put", full.Secret, masked, false); w.Code != 409 {
		t.Fatalf("new resource borrowed an existing masked proof: %d", w.Code)
	}
	if w = request("node.get", read.Secret, map[string]string{"id": "private"}, true); w.Code != 403 {
		t.Fatal("ordinary reader retrieved secrets", w.Code)
	}
	w = request("node.get", full.Secret, map[string]string{"id": "private"}, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), input.Chain[0].Shadowsocks.Password) {
		t.Fatal("authorized explicit secret retrieval failed", w.Code)
	}
	events, err := s.Events(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Event == "secret.retrieval_authorized" {
			found = true
			if event.ActorID != admin.ID || event.CredentialID != full.ID || event.SubjectID != "POST /api/v2/rpc/node.get" {
				t.Fatal("incomplete retrieval audit", event)
			}
		}
		encoded, _ := json.Marshal(event)
		if strings.Contains(string(encoded), input.Chain[0].Shadowsocks.Password) {
			t.Fatal("security audit contains an upstream proof")
		}
	}
	if !found {
		t.Fatal("secret read lacked a durable management audit")
	}
	// A writer can submit credentials it already possesses without gaining a
	// reusable secret-read capability. Preview and commit responses stay masked.
	importer, err := s.IssueToken(t.Context(), principal(admin), admin.ID, []Permission{NodesRead, NodesWrite, SecretsManage}, 0)
	if err != nil {
		t.Fatal(err)
	}
	source := "trojan://caller-supplied-private-proof@server.example:443#Imported"
	w = request("nodes.import.preview", importer.Secret, contractnode.ImportRequest{Text: source}, false)
	var preview contractnode.ImportPreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &preview) != nil || len(preview.Items) != 1 || strings.Contains(w.Body.String(), "caller-supplied-private-proof") {
		t.Fatalf("unsafe import preview: %d %s", w.Code, w.Body.String())
	}
	commit := contractnode.ImportCommit{Text: source, IDs: []string{preview.Items[0].ID}}
	w = request("nodes.import.commit", edit.Secret, commit, false)
	var outcome contractnode.ImportResults
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &outcome) != nil || len(outcome.Items) != 1 || outcome.Items[0].Saved {
		t.Fatalf("import bypassed secret management: %d %s", w.Code, w.Body.String())
	}
	w = request("nodes.import.commit", importer.Secret, commit, false)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &outcome) != nil || len(outcome.Items) != 1 || !outcome.Items[0].Saved || strings.Contains(w.Body.String(), "caller-supplied-private-proof") {
		t.Fatalf("secret-safe source import failed: %d %s", w.Code, w.Body.String())
	}
	imported, err := nodes.Get(t.Context(), commit.IDs[0])
	encodedImport, encodeErr := json.Marshal(imported)
	if err != nil || encodeErr != nil || !strings.Contains(string(encodedImport), "caller-supplied-private-proof") {
		t.Fatal("import lost the caller's proof", err)
	}
	if w = request("node.get", importer.Secret, map[string]string{"id": commit.IDs[0]}, true); w.Code != 403 {
		t.Fatal("importer acquired secret read access", w.Code)
	}
	if _, err := s.db.ExecContext(t.Context(), `CREATE TRIGGER fail_secret_audit BEFORE INSERT ON management_security_events BEGIN SELECT RAISE(ABORT,'audit unavailable');END`); err != nil {
		t.Fatal(err)
	}
	changed := stored
	changed.Chain[0].Shadowsocks.Password = "replacement-blocked-by-failed-audit"
	w = request("node.put", full.Secret, changed, false)
	if w.Code != 503 {
		t.Fatal("secret mutation succeeded without durable authorization audit", w.Code)
	}
	persisted, err := nodes.Get(t.Context(), input.ID)
	if err != nil || persisted.Chain[0].Shadowsocks.Password != input.Chain[0].Shadowsocks.Password {
		t.Fatal("audit failure changed private configuration", err)
	}
	w = request("node.get", full.Secret, map[string]string{"id": "private"}, true)
	if w.Code != 503 || strings.Contains(w.Body.String(), input.Chain[0].Shadowsocks.Password) {
		t.Fatal("secret retrieval succeeded without durable auditing", w.Code)
	}
	if w = request("node.get", read.Secret, map[string]string{"id": "private"}, false); w.Code != 200 {
		t.Fatal("secret audit failure blocked a masked configuration read", w.Code)
	}
}

func TestRawDiagnosticsRequireSecretReadIndependently(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	narrow, err := s.IssueToken(t.Context(), principal(admin), admin.ID, []Permission{Diagnostics}, 0)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	called := false
	mux.HandleFunc("GET /debug/pprof/heap", func(http.ResponseWriter, *http.Request) { called = true })
	gate := (&Server{Store: s, Permissions: map[string]Permission{"GET /debug/pprof/heap": Diagnostics}}).Wrap(mux)
	r := httptest.NewRequest("GET", "/debug/pprof/heap", nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+narrow.Secret)
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, r)
	if w.Code != 403 || called {
		t.Fatal("diagnostic privilege bypassed reusable secret isolation", w.Code)
	}
}

func TestSensitiveOperationsProtectRPCAndFriendlyAliases(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	for _, test := range []struct {
		pattern    string
		permission Permission
	}{
		{"POST /api/v2/rpc/backup.run", BackupManage}, {"POST /api/v2/backup/run", BackupManage},
		{"POST /api/v2/rpc/backup.restore", BackupManage}, {"POST /api/v2/backup/restore", BackupManage},
		{"POST /api/v2/rpc/tools.logs", Diagnostics}, {"GET /api/v2/tools/logs", Diagnostics}, {"GET /api/v2/tools/logs/v2", Diagnostics},
		{"POST /api/v2/rpc/gateway.ca.import", GatewayWrite}, {"POST /api/v2/gateway/ca/import", GatewayWrite},
		{"POST /api/v2/rpc/gateway.ca.generate", GatewayWrite}, {"POST /api/v2/gateway/ca/generate", GatewayWrite},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			issued, err := s.IssueToken(t.Context(), principal(admin), admin.ID, []Permission{test.permission}, 0)
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			called := false
			mux.HandleFunc(test.pattern, func(http.ResponseWriter, *http.Request) { called = true })
			method, path, _ := strings.Cut(test.pattern, " ")
			r := httptest.NewRequest(method, path, nil)
			r.TLS = &tls.ConnectionState{}
			r.Header.Set("Authorization", "Bearer "+issued.Secret)
			w := httptest.NewRecorder()
			(&Server{Store: s, Permissions: map[string]Permission{test.pattern: test.permission}}).Wrap(mux).ServeHTTP(w, r)
			if w.Code != 403 || called {
				t.Fatal("alias bypassed secret isolation", w.Code)
			}
		})
	}
}
