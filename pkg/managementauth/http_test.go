package managementauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManagementGateAuthenticationScopeAndUnknownRoutes(t *testing.T) {
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
	narrow, err := s.IssueToken(t.Context(), principal(admin), admin.ID, []Permission{NodesRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	permissions := map[string]Permission{"POST /api/v2/rpc/nodes.get": NodesRead, "POST /api/v2/rpc/node.put": NodesWrite, "GET /metrics": MetricsRead, "GET /debug/pprof/": Diagnostics, "GET /api/v2/events": ConnectionsRead}
	called := 0
	for pattern := range permissions {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if _, ok := FromContext(r.Context()); !ok {
				t.Error("handler lacks principal")
			}
			called++
			w.WriteHeader(http.StatusOK)
		})
	}
	mux.HandleFunc("POST /api/v2/rpc/new.sensitive.action", func(http.ResponseWriter, *http.Request) { t.Error("unclassified handler executed") })
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server := &Server{Store: s, Permissions: permissions, AcceptOrigin: func(origin string, _ *http.Request) bool { return origin == "https://trusted.example" }}
	gate := server.Wrap(mux)
	for _, tt := range []struct {
		name, method, path, authorization, origin, peer string
		tls                                             bool
		want                                            int
	}{
		{"missing", "POST", "/api/v2/rpc/nodes.get", "", "", "", true, 401},
		{"bad bearer", "POST", "/api/v2/rpc/nodes.get", "Bearer bad", "", "", true, 401},
		{"basic rejected", "POST", "/api/v2/rpc/nodes.get", "Basic YTpi", "", "", true, 401},
		{"query rejected", "POST", "/api/v2/rpc/nodes.get?token=" + full.Secret, "Bearer " + full.Secret, "", "", true, 401},
		{"read permitted", "POST", "/api/v2/rpc/nodes.get", "Bearer " + read.Secret, "", "", true, 200},
		{"read mutation denied", "POST", "/api/v2/rpc/node.put", "Bearer " + read.Secret, "", "", true, 403},
		{"scope enforced", "POST", "/api/v2/rpc/node.put", "Bearer " + narrow.Secret, "", "", true, 403},
		{"metrics auth", "GET", "/metrics", "", "", "", true, 401},
		{"metrics read", "GET", "/metrics", "Bearer " + read.Secret, "", "", true, 200},
		{"profiling denied", "GET", "/debug/pprof/heap", "Bearer " + read.Secret, "", "", true, 403},
		{"profiling allowed", "GET", "/debug/pprof/heap", "Bearer " + full.Secret, "", "", true, 200},
		{"stream auth", "GET", "/api/v2/events", "", "", "", true, 401},
		{"new action denies admin", "POST", "/api/v2/rpc/new.sensitive.action", "Bearer " + full.Secret, "", "", true, 403},
		{"alternate method", "GET", "/api/v2/rpc/node.put", "Bearer " + full.Secret, "", "", true, 403},
		{"remote plaintext", "POST", "/api/v2/rpc/nodes.get", "Bearer " + full.Secret, "", "192.0.2.10:1000", false, 403},
		{"actual local peer", "POST", "/api/v2/rpc/nodes.get", "Bearer " + full.Secret, "", "127.0.0.1:1000", false, 200},
		{"untrusted origin", "POST", "/api/v2/rpc/nodes.get", "Bearer " + full.Secret, "https://evil.example", "", true, 403},
		{"trusted preflight", "OPTIONS", "/api/v2/rpc/nodes.get", "", "https://trusted.example", "", true, 204},
		{"public UI", "GET", "/index.html", "", "", "", true, 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, nil)
			r.RemoteAddr = tt.peer
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			r.Header.Set("Authorization", tt.authorization)
			r.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			gate.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tt.want, w.Body.String())
			}
			if tt.want != 200 && tt.want != 204 && (strings.Contains(w.Body.String(), full.Secret) || strings.Contains(w.Body.String(), "sql")) {
				t.Fatal("sensitive error response")
			}
		})
	}
	if called != 4 {
		t.Fatalf("protected handlers called %d times, want 4", called)
	}
}

func TestStreamStopsAfterRevocation(t *testing.T) {
	s := testStore(t)
	u := testUser(t, s, "admin", Admin)
	token, err := s.IssueToken(t.Context(), principal(u), u.ID, []Permission{ConnectionsRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	started := make(chan struct{})
	stopped := make(chan struct{})
	mux.HandleFunc("GET /api/v2/events", func(_ http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(stopped) })
	gate := (&Server{Store: s, Permissions: map[string]Permission{"GET /api/v2/events": ConnectionsRead}}).Wrap(mux)
	r := httptest.NewRequest("GET", "/api/v2/events", nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+token.Secret)
	done := make(chan struct{})
	go func() { defer close(done); gate.ServeHTTP(httptest.NewRecorder(), r) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("stream did not start")
	}
	if err := s.Revoke(t.Context(), principal(u), token.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked stream kept running")
	}
	<-done
}

func TestLoginRateLimitsAndRawPasswordRejection(t *testing.T) {
	s := testStore(t)
	p, err := NewPasswordService(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: s, Passwords: p}
	mux := http.NewServeMux()
	server.Register(mux)
	gate := server.Wrap(mux)
	request := func(body string, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1000"
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w
	}
	if got := request(`{"login":"admin","password":"should-not-be-accepted"}`, "/api/v2/auth/login"); got.Code != 400 || strings.Contains(got.Body.String(), "should-not-be-accepted") {
		t.Fatalf("raw password response=%d %s", got.Code, got.Body.String())
	}
	for range 19 {
		if got := request(`{"login":"unknown"}`, "/api/v2/auth/parameters"); got.Code != 200 {
			t.Fatalf("premature limit: %d", got.Code)
		}
	}
	if got := request(`{"login":"unknown"}`, "/api/v2/auth/parameters"); got.Code != 429 {
		t.Fatalf("rate limit status=%d", got.Code)
	}
	p.mu.Lock()
	p.rates = make(map[string]rateWindow)
	p.global = rateWindow{}
	p.mu.Unlock()
	for n := range 120 {
		if !p.allow(string(rune(n + 1000))) {
			t.Fatal("unexpected global limit")
		}
	}
	if p.allow("new peer") {
		t.Fatal("global login rate limit missing")
	}
}

func TestUserTokenAPIsAndSecretResponse(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	token, err := s.IssueToken(t.Context(), principal(admin), admin.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: s}
	mux := http.NewServeMux()
	server.Register(mux)
	gate := server.Wrap(mux)
	request := func(method, path string, body any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		r.RemoteAddr = "[::1]:1000"
		r.Header.Set("Authorization", "Bearer "+token.Secret)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w
	}
	w := request("POST", "/api/v2/auth/users", map[string]string{"login": "new-reader", "role": ReadOnly})
	if w.Code != 200 {
		t.Fatalf("create user: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		User       User             `json:"user"`
		Enrollment IssuedCredential `json:"enrollment"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Enrollment.Secret == "" {
		t.Fatal("enrollment capability missing")
	}
	w = request("GET", "/api/v2/auth/users", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), created.Enrollment.Secret) {
		t.Fatal("user listing leaked credential")
	}
	w = request("PUT", "/api/v2/auth/users/"+created.User.ID, map[string]any{"login": "new-reader", "role": ReadOnly, "disabled": true})
	if w.Code != 200 {
		t.Fatalf("disable: %d", w.Code)
	}
	w = request("POST", "/api/v2/auth/tokens", map[string]any{"scopes": []Permission{NodesRead}})
	if w.Code != 200 {
		t.Fatalf("token creation: %d %s", w.Code, w.Body.String())
	}
	var issued IssuedCredential
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	w = request("GET", "/api/v2/auth/tokens", nil)
	if strings.Contains(w.Body.String(), issued.Secret) {
		t.Fatal("secret returned more than once")
	}
	if got := request("DELETE", "/api/v2/auth/tokens/"+issued.ID, nil); got.Code != 200 {
		t.Fatalf("revoke=%d", got.Code)
	}
	if _, err := s.Authenticate(context.Background(), issued.Secret, "token"); err == nil {
		t.Fatal("API-revoked token accepted")
	}
}
