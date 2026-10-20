package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagementRPCOriginPolicy(t *testing.T) {
	policy := newManagementOriginPolicy()
	cases := []struct {
		name, peer, origin string
		auth               *Auth
		allow              bool
	}{
		{"local CLI", "127.0.0.1:1234", "", nil, true},
		{"local browser", "127.0.0.1:1234", "http://localhost:50051", nil, true},
		{"mapped loopback browser", "[::ffff:127.0.0.1]:1234", "http://localhost:50051", nil, true},
		{"official static frontend", "127.0.0.1:1234", officialGatewayUIOrigin, nil, true},
		{"official static frontend IPv6", "[::1]:1234", officialGatewayUIOrigin, nil, true},
		{"remote client no origin", "192.0.2.10:1234", "", nil, false},
		{"remote client trusted origin", "192.0.2.10:1234", officialGatewayUIOrigin, nil, false},
		{"untrusted website", "127.0.0.1:1234", "https://attacker.example", nil, false},
		{"untrusted github pages", "127.0.0.1:1234", "https://attacker.github.io", nil, false},
		{"suffix confusion", "127.0.0.1:1234", "https://yuhaiin.github.io.attacker.example", nil, false},
		{"host confusion", "127.0.0.1:1234", "https://yuhaiin.github.io@attacker.example", nil, false},
		{"http official page", "127.0.0.1:1234", "http://yuhaiin.github.io", nil, false},
		{"unexpected official port", "127.0.0.1:1234", "https://yuhaiin.github.io:444", nil, false},
		{"opaque origin", "127.0.0.1:1234", "null", nil, false},
		{"untrusted same-host DNS rebinding", "127.0.0.1:1234", "http://attacker.example", nil, false},
		{"authenticated remote native client", "192.0.2.10:1234", "", NewAuth("a", "b"), true},
		{"authenticated remote same-origin", "192.0.2.10:1234", "http://127.0.0.1:50051", NewAuth("a", "b"), true},
		{"authenticated remote unrelated origin", "192.0.2.10:1234", "https://attacker.example", NewAuth("a", "b"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:50051/api/v2/rpc/settings.load", nil)
			request.RemoteAddr = tc.peer
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if got := policy.authorize(tc.auth, request); got != tc.allow {
				t.Fatalf("allowed=%v want=%v", got, tc.allow)
			}
		})
	}

	policy.set([]string{"https://trusted.example"})
	t.Run("custom allowlist", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:50051/api/v2/rpc/settings.save", nil)
		request.RemoteAddr = "127.0.0.1:1234"
		request.Header.Set("Origin", "https://trusted.example")
		if !policy.authorize(nil, request) {
			t.Fatal("trusted custom origin should work on loopback")
		}
		policy.set(nil)
		if policy.authorize(nil, request) {
			t.Fatal("removed custom origin should immediately stop working")
		}
	})
}

func TestManagementRPCCORSAndAuthentication(t *testing.T) {
	policy := newManagementOriginPolicy()
	for _, name := range []string{
		"gateway.workspace.get", "gateway.workspace.save", "gateway.ca.import",
		"settings.load", "settings.save", "routing.rules.list",
	} {
		t.Run(name, func(t *testing.T) {
			pattern := "POST /api/v2/rpc/" + name
			mux := http.NewServeMux()
			called := false
			handleRPCFunc(mux, nil, policy, pattern, func(w http.ResponseWriter, _ *http.Request) error {
				called = true
				return nil
			})
			for _, tc := range []struct {
				origin string
				status int
			}{
				{officialGatewayUIOrigin, http.StatusOK},
				{"https://attacker.example", http.StatusForbidden},
			} {
				called = false
				request := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/"+name, nil)
				request.RemoteAddr = "127.0.0.1:1111"
				request.Header.Set("Origin", tc.origin)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, request)
				if rec.Code != tc.status || called != (tc.status == http.StatusOK) {
					t.Fatalf("origin=%q status=%d called=%v, wanted %d", tc.origin, rec.Code, called, tc.status)
				}
				if tc.status == http.StatusOK {
					if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.origin {
						t.Fatalf("allow origin = %q", got)
					}
					if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
						t.Fatalf("allow credentials = %q", got)
					}
				} else if rec.Header().Get("Access-Control-Allow-Origin") != "" {
					t.Fatal("rejected site must not receive CORS permission")
				}
			}
		})
	}
}

func TestManagementOriginPreflight(t *testing.T) {
	policy := newManagementOriginPolicy()
	for _, tc := range []struct {
		origin, peer string
		status       int
	}{
		{officialGatewayUIOrigin, "127.0.0.1:1234", http.StatusNoContent},
		{"https://attacker.example", "127.0.0.1:1234", http.StatusForbidden},
		{officialGatewayUIOrigin, "192.0.2.2:1234", http.StatusForbidden},
	} {
		mux := http.NewServeMux()
		handleRPCFunc(mux, nil, policy, "OPTIONS /api/v2/rpc/", func(w http.ResponseWriter, _ *http.Request) error {
			return nil
		})
		req := httptest.NewRequest(http.MethodOptions, "/api/v2/rpc/settings.save", nil)
		req.RemoteAddr = tc.peer
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != tc.status {
			t.Fatalf("origin=%q peer=%q code=%d want %d", tc.origin, tc.peer, rr.Code, tc.status)
		}
	}
}

func TestTrustedOriginValidation(t *testing.T) {
	for _, tc := range []struct {
		origins []string
		valid   bool
	}{
		{nil, true},
		{[]string{"https://example.com", "https://user.example:8443"}, true},
		{[]string{"http://localhost:5173"}, true},
		{[]string{"http://127.0.0.1:5173"}, true},
		{[]string{"http://example.com"}, false},
		{[]string{"https://*.example.com"}, false},
		{[]string{"https://example.com/path"}, false},
		{[]string{"https://example.com/?q=1"}, false},
		{[]string{"null"}, false},
		{[]string{"https://example.com", "https://example.com"}, false},
	} {
		err := validateTrustedOrigins(tc.origins)
		if (err == nil) != tc.valid {
			t.Fatalf("origins=%q valid=%v err=%v", tc.origins, tc.valid, err)
		}
	}
}
