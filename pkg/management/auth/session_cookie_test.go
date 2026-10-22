package auth

import (
	"crypto/tls"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookieSessionRestoresAndRevokesAcrossRefresh(t *testing.T) {
	s := testStore(t)
	u := testUser(t, s, "admin", Admin)
	issued := testSession(t, s, u)
	server := &Server{Store: s, AcceptOrigin: func(origin string, _ *http.Request) bool { return origin == "https://ui.example" }}
	mux := http.NewServeMux()
	server.Register(mux)
	gate := server.Wrap(mux)
	login := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "https://controller.example/api/v2/auth/login", nil)
	setSessionCookie(login, request, issued)
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing persistent session cookie")
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-yuhaiin-session" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteNoneMode || cookie.MaxAge <= 0 || cookie.Expires.Unix() != issued.ExpiresAt {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	do := func(method, path, origin, authorization string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://controller.example/api/v2/auth"+path, nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", origin)
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w
	}
	// A freshly loaded page has no header secret, only the HttpOnly cookie.
	w := do("GET", "/session", "https://ui.example", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), issued.Secret) || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	var restored struct {
		Principal Principal `json:"principal"`
		ExpiresAt int64     `json:"expiresAt"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Principal.UserID != u.ID || restored.Principal.CredentialID != issued.ID || restored.ExpiresAt != issued.ExpiresAt {
		t.Fatal("restore changed identity or extended expiry")
	}
	if w := do("GET", "/session", "", ""); w.Code != 200 {
		t.Fatal("same-origin GET without Origin failed")
	}
	if w := do("DELETE", "/sessions/"+issued.ID, "", ""); w.Code != 403 {
		t.Fatal("cookie mutation without Origin accepted")
	}
	if w := do("DELETE", "/session", "https://evil.example", ""); w.Code != 403 {
		t.Fatal("cross-site logout accepted")
	}
	if w := do("GET", "/session", "https://ui.example", "Bearer invalid"); w.Code != 401 {
		t.Fatal("invalid header fell back to cookie")
	}
	if w := do("GET", "/session?token=invalid", "https://ui.example", ""); w.Code != 401 {
		t.Fatal("query credential accepted with cookie")
	}
	w = do("DELETE", "/session", "https://ui.example", "")
	if w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	cleared := w.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge != -1 {
		t.Fatal("logout did not clear cookie")
	}
	if w := do("GET", "/session", "https://ui.example", ""); w.Code != 401 {
		t.Fatal("logged-out cookie restored session")
	}
}

func TestCookieSecurityAndSessionExpiry(t *testing.T) {
	issued := IssuedCredential{ExpiresAt: time.Now().Add(time.Hour).Unix(), Secret: "opaque"}
	for _, secure := range []bool{false, true} {
		r := httptest.NewRequest("GET", "http://localhost/", nil)
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		setSessionCookie(w, r, issued)
		cookie := w.Result().Cookies()[0]
		if cookie.Secure != secure || !cookie.HttpOnly || cookie.Domain != "" || (!secure && cookie.SameSite != http.SameSiteLaxMode) {
			t.Fatal("wrong local/TLS cookie policy")
		}
	}
}

func TestTunnelSessionCookieUsesPublicHTTPS(t *testing.T) {
	r := httptest.NewRequest("POST", "http://management.example/api/v2/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:1000"
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	setSessionCookie(w, r, IssuedCredential{ExpiresAt: time.Now().Add(time.Hour).Unix(), Secret: "opaque"})
	cookie := w.Result().Cookies()[0]
	if cookie.Name != "__Host-yuhaiin-session" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode {
		t.Fatalf("tunnel HTTPS cookie flags: name=%s secure=%v httpOnly=%v sameSite=%v", cookie.Name, cookie.Secure, cookie.HttpOnly, cookie.SameSite)
	}
	r.AddCookie(cookie)
	secret, kind := credentials(r)
	if secret != "opaque" || kind != "session" {
		t.Fatal("tunnel session cookie cannot authenticate after refresh")
	}
}
