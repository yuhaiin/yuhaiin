package app

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/managementauth"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestApplicationManagementGateCoversActualRoutes(t *testing.T) {
	dir := t.TempDir()
	inner := http.NewServeMux()
	httpapi.RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		handleFunc(inner, nil, nil, pattern, handler)
	}, httpapi.V2Services{})
	RegisterHTTP(inner)
	// Match the auxiliary registrations made during Start and profiler setup.
	for _, pattern := range []string{"GET /metrics", "GET /debug/profiler/", "GET /api/v2/profiler/sessions", "POST /api/v2/profiler/sessions", "DELETE /api/v2/profiler/sessions/{id}"} {
		inner.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	}
	app := &AppInstance{StartOptions: &StartOptions{ConfigPath: dir, Auth: NewAuth("legacy", "password")}, Mux: inner, Setting: NewSettingsController(nil, dir, nil), closers: &closers{}}
	if err := app.protectManagement(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.closers.Close() })
	for pattern := range httpapi.ManagementPermissions() {
		method, path, _ := strings.Cut(pattern, " ")
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "127.0.0.1:1000"
		w := httptest.NewRecorder()
		app.Mux.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("unprotected v2 registration %s: %d", pattern, w.Code)
		}
	}
	for _, path := range []string{"/metrics", "/debug/pprof/heap", "/debug/pprof/profile", "/debug/profiler/example/", "/api/v2/profiler/sessions"} {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "127.0.0.1:1000"
		w := httptest.NewRecorder()
		app.Mux.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("auxiliary %s status=%d", path, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/v2/rpc/settings.get", nil)
	r.RemoteAddr = "127.0.0.1:1000"
	r.SetBasicAuth("legacy", "password")
	w := httptest.NewRecorder()
	app.Mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("legacy Basic bypassed IAM: %d", w.Code)
	}
	db, err := storagesqlite.OpenManagement(t.Context(), filepath.Join(dir, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := managementauth.NewStore(db.DB())
	user, capability, err := store.CreateUser(t.Context(), "local", "admin", managementauth.Admin, true)
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := managementauth.NewPasswordService(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	// A fixed derived credential is enough to exercise the registration gate.
	credential := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err := passwords.Enroll(t.Context(), capability.Secret, credential); err != nil {
		t.Fatal(err)
	}
	session, err := passwords.Login(t.Context(), user.Login, credential)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/metrics", 204},
		{"GET", "/debug/profiler/example/", 204},
		{"POST", "/api/v2/rpc/future.privileged.action", 403},
	} {
		r := httptest.NewRequest(tt.method, tt.path, strings.NewReader("{}"))
		r.RemoteAddr = "127.0.0.1:1000"
		r.Header.Set("Authorization", "Session "+session.Secret)
		w := httptest.NewRecorder()
		app.Mux.ServeHTTP(w, r)
		if w.Code != tt.want {
			t.Errorf("%s: %d want %d", tt.path, w.Code, tt.want)
		}
	}
	r = httptest.NewRequest("POST", "http://attacker.example/api/v2/auth/parameters", strings.NewReader(`{"login":"admin"}`))
	r.RemoteAddr = "127.0.0.1:1000"
	r.Header.Set("Origin", "http://attacker.example")
	w = httptest.NewRecorder()
	app.Mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("DNS rebinding origin accepted")
	}
}
