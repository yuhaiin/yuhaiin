package app

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	managementauth "github.com/Asutorufa/yuhaiin/pkg/management/auth"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// Use the actual app registrations and outer identity middleware: a Tunnel
// terminates public HTTPS and reaches the local controller over loopback HTTP.
func TestManagementTunnelSameOrigin(t *testing.T) {
	dir := t.TempDir()
	mux := http.NewServeMux()
	RegisterHTTP(mux)
	app := &AppInstance{StartOptions: &StartOptions{ConfigPath: dir, HTTPMiddleware: managementauth.Middleware}, Mux: mux, Setting: NewSettingsController(nil, dir, nil), closers: &closers{}}
	if err := app.protectManagement(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.closers.Close() })
	for _, tc := range []struct {
		name, method, path, origin, peer, forwarded string
		tls                                         bool
		want                                        int
	}{
		{name: "direct navigation", method: "GET", path: "/", peer: "127.0.0.1:1000", want: 200},
		{name: "originless setup discovery", method: "GET", path: "/api/v2/auth/setup", peer: "127.0.0.1:1000", forwarded: "https", want: 200},
		{name: "tunnel same-origin login parameters", method: "POST", path: "/api/v2/auth/parameters", origin: "https://management.example", peer: "127.0.0.1:1000", forwarded: "https", want: 200},
		{name: "TLS loopback same-origin login parameters", method: "POST", path: "/api/v2/auth/parameters", origin: "https://management.example", peer: "127.0.0.1:1000", tls: true, want: 200},
		{name: "untrusted site", method: "POST", path: "/api/v2/auth/parameters", origin: "https://attacker.example", peer: "127.0.0.1:1000", forwarded: "https", want: 403},
		{name: "DNS rebinding without forwarded HTTPS", method: "POST", path: "/api/v2/auth/parameters", origin: "http://management.example", peer: "127.0.0.1:1000", want: 403},
		{name: "remote forged forwarded scheme", method: "POST", path: "/api/v2/auth/parameters", origin: "https://management.example", peer: "192.0.2.1:1000", forwarded: "https", want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://management.example"+tc.path, strings.NewReader(`{"login":"admin"}`))
			r.RemoteAddr = tc.peer
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-Forwarded-Proto", tc.forwarded)
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			app.Mux.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestManagementTunnelLoginRefreshAndLogout(t *testing.T) {
	dir := t.TempDir()
	mux := http.NewServeMux()
	RegisterHTTP(mux)
	app := &AppInstance{StartOptions: &StartOptions{ConfigPath: dir, HTTPMiddleware: managementauth.Middleware}, Mux: mux, Setting: NewSettingsController(nil, dir, nil), closers: &closers{}}
	if err := app.protectManagement(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.closers.Close() })
	db, err := storagesqlite.OpenManagement(t.Context(), filepath.Join(dir, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := managementauth.NewStore(db.DB())
	user, enrollment, err := store.CreateUser(t.Context(), "local", "admin", managementauth.Admin, true)
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := managementauth.NewPasswordService(t.Context(), store)
	if err != nil {
		t.Fatal(err)
	}
	derived := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err := passwords.Enroll(t.Context(), enrollment.Secret, derived); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, origin, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "http://management.example"+path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1000"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		app.Mux.ServeHTTP(w, r)
		return w
	}
	login := request("POST", "/api/v2/auth/login", "https://management.example", `{"login":"admin","clientCredential":"`+derived+`"}`, nil)
	if login.Code != 200 {
		t.Fatalf("tunnel login status=%d", login.Code)
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-yuhaiin-session" || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("tunnel login did not issue a secure HttpOnly cookie")
	}
	cookie := cookies[0]
	var issued managementauth.IssuedCredential
	if err := json.Unmarshal(login.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	refresh := request("GET", "/api/v2/auth/session", "", "", cookie)
	if refresh.Code != 200 || strings.Contains(refresh.Body.String(), issued.Secret) {
		t.Fatalf("tunnel refresh status=%d", refresh.Code)
	}
	var restored struct {
		Principal managementauth.Principal `json:"principal"`
		ExpiresAt int64                    `json:"expiresAt"`
	}
	if err := json.Unmarshal(refresh.Body.Bytes(), &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Principal.UserID != user.ID || restored.Principal.CredentialID != issued.ID || restored.ExpiresAt != issued.ExpiresAt {
		t.Fatal("refresh replaced or extended the tunnel session")
	}
	if denied := request("DELETE", "/api/v2/auth/session", "https://attacker.example", "", cookie); denied.Code != 403 {
		t.Fatal("cross-site cookie logout accepted")
	}
	logout := request("DELETE", "/api/v2/auth/session", "https://management.example", "", cookie)
	if logout.Code != 200 {
		t.Fatalf("tunnel logout status=%d", logout.Code)
	}
	cleared := logout.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != cookie.Name || !cleared[0].Secure || cleared[0].MaxAge != -1 {
		t.Fatal("tunnel logout did not expire the HTTPS cookie")
	}
	if stale := request("GET", "/api/v2/auth/session", "", "", cookie); stale.Code != 401 {
		t.Fatal("revoked tunnel session restored")
	}
}
