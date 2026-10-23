package auth

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	usage "github.com/Asutorufa/yuhaiin/pkg/contract/usage"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
)

func TestUsageHTTPScopesAndOwnerIsolation(t *testing.T) {
	runtime, err := OpenRuntime(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	admin := testUser(t, runtime.store, "admin", Admin)
	alice := testUser(t, runtime.store, "alice", NoManagement)
	bob := testUser(t, runtime.store, "bob", NoManagement)
	issue := func(owner User, scopes []Permission) string {
		t.Helper()
		out, err := runtime.store.IssueToken(t.Context(), principal(admin), owner.ID, scopes, 0)
		if err != nil {
			t.Fatal(err)
		}
		return out.Secret
	}
	self := issue(alice, []Permission{UsageOwn})
	narrow := issue(alice, []Permission{IdentityRead})
	full := issue(admin, nil)
	connections := statistics.NewSQLiteConnStore(filepath.Join(t.TempDir(), "state.db"), nil)
	defer connections.Close()
	recorder, err := connections.EnableUserUsage(statistics.DefaultUsageOptions())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	gate, _, err := runtime.Middleware(t.Context(), mux, httpapi.MiddlewareOptions{UserUsage: recorder})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		path, token string
		code        int
	}{
		{"/usage", self, 200}, {"/usage?owner=" + alice.ID, self, 200}, {"/usage?owner=" + bob.ID, self, 403}, {"/usage?owner=unattributed", self, 403},
		{"/usage/audit?owner=" + bob.ID, self, 403}, {"/usage/audit", self, 200}, {"/usage/owners", self, 403}, {"/usage", narrow, 403},
		{"/usage?owner=" + bob.ID, full, 200}, {"/usage?owner=unattributed", full, 200}, {"/usage/owners", full, 200},
		{"/usage?from=nope", self, 400}, {"/usage?interval=second", self, 400}, {"/usage/audit?limit=201", self, 400}, {"/usage/audit?before=not-a-cursor", self, 400},
	} {
		w := request("GET", "/api/v2/auth"+tc.path, "", tc.token)
		if w.Code != tc.code {
			t.Errorf("%s=%d want %d body=%s", tc.path, w.Code, tc.code, w.Body)
		}
	}
	w := request("GET", "/api/v2/auth/usage", "", self)
	var report usage.Report
	if json.Unmarshal(w.Body.Bytes(), &report) != nil || report.Summary.UserID != alice.ID {
		t.Fatalf("report=%s", w.Body)
	}
	settings := `{"auditDays":7,"maxAuditRows":5000,"hourlyDays":14,"dailyDays":365}`
	if w := request("PUT", "/api/v2/auth/usage/settings", settings, self); w.Code != 403 {
		t.Fatalf("self changed retention: %d", w.Code)
	}
	if w := request("PUT", "/api/v2/auth/usage/settings", settings, full); w.Code != 200 {
		t.Fatalf("settings=%d %s", w.Code, w.Body)
	}
	if recorder.Options().AuditDays != 7 {
		t.Fatal("retention not applied")
	}
	events, eventErr := runtime.store.Events(t.Context())
	if eventErr != nil {
		t.Fatal(eventErr)
	}
	if len(events) == 0 || events[0].Event != "usage.retention_updated" || events[0].Source != "127.0.0.1" || events[0].Method != "PUT" || events[0].Result != "succeeded" || events[0].CredentialID == "" {
		t.Fatalf("management audit=%+v", events)
	}
	if w := request("PUT", "/api/v2/auth/usage/settings", `{"auditDays":0}`, full); w.Code != 400 {
		t.Fatalf("invalid retention=%d", w.Code)
	}
}
