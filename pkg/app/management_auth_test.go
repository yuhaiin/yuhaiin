package app

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
	app := &AppInstance{StartOptions: &StartOptions{ConfigPath: dir, Auth: NewAuth("legacy", "password"), HTTPMiddleware: managementauth.Middleware}, Mux: inner, Setting: NewSettingsController(nil, dir, nil), closers: &closers{}}
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

func TestLocalManagementWithoutIdentityMiddleware(t *testing.T) {
	dir := t.TempDir()
	mux := http.NewServeMux()
	RegisterHTTP(mux)
	for _, pattern := range []string{"POST /api/v2/rpc/settings.put", "GET /api/v2/tools/logs/v2", "GET /metrics", "GET /api/v2/profiler/sessions"} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	}
	instance := &AppInstance{StartOptions: &StartOptions{ConfigPath: dir}, Mux: mux, Setting: NewSettingsController(nil, dir, nil), closers: &closers{}}
	if err := instance.protectManagement(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		method, path, peer, origin string
		want                       int
	}{
		{"GET", "/api/v2/management", "127.0.0.1:1", "", 200},
		{"POST", "/api/v2/rpc/settings.put", "127.0.0.1:1", "http://127.0.0.1:50051", 204},
		{"GET", "/api/v2/tools/logs/v2", "[::1]:1", "", 204},
		{"GET", "/metrics", "127.0.0.1:1", "", 204},
		{"GET", "/api/v2/profiler/sessions", "127.0.0.1:1", "", 204},
		{"GET", "/api/v2/auth/setup", "127.0.0.1:1", "", 404},
		{"GET", "/api/v2/auth/users", "127.0.0.1:1", "", 404},
		{"GET", "/api/v2/management", "192.0.2.1:1", "", 403},
		{"POST", "/api/v2/rpc/settings.put", "192.0.2.1:1", "https://yuhaiin.github.io", 403},
		{"GET", "/metrics", "192.0.2.1:1", "", 403},
		{"GET", "/api/v2/profiler/sessions", "192.0.2.1:1", "", 403},
		{"GET", "/api/v2/management", "127.0.0.1:1", "http://attacker.example", 403},
		{"OPTIONS", "/api/v2/management", "127.0.0.1:1", "http://localhost:5173", 204},
	} {
		r := httptest.NewRequest(tt.method, "http://127.0.0.1:50051"+tt.path, nil)
		r.RemoteAddr = tt.peer
		r.Header.Set("Origin", tt.origin)
		w := httptest.NewRecorder()
		instance.Mux.ServeHTTP(w, r)
		if w.Code != tt.want {
			t.Errorf("%s %s peer=%s origin=%s: %d want %d", tt.method, tt.path, tt.peer, tt.origin, w.Code, tt.want)
		}
		if tt.path == "/api/v2/management" && w.Code == 200 && w.Body.String() != `{"authentication":"none"}` {
			t.Fatal("native mode did not advertise no identity module")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "management.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("native mode created an identity database: %v", err)
	}
}

func TestManagementMiddlewareFailureDoesNotFallBack(t *testing.T) {
	want := errors.New("identity store unavailable")
	instance := &AppInstance{StartOptions: &StartOptions{HTTPMiddleware: func(context.Context, *http.ServeMux, httpapi.MiddlewareOptions) (http.Handler, io.Closer, error) {
		return nil, nil, want
	}}, Mux: http.NewServeMux(), closers: &closers{}}
	if err := instance.protectManagement(t.Context()); !errors.Is(err, want) {
		t.Fatalf("middleware failure did not abort: %v", err)
	}
}
