package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnauthenticatedGatewayManagementIsLocalOnly(t *testing.T) {
	tests := []struct {
		name, peer, origin string
		allowed            bool
	}{
		{"loopback cli without origin", "127.0.0.1:1234", "", true},
		{"ipv6 local ui", "[::1]:1234", "http://localhost:50051", true},
		{"ipv4 local ui", "127.0.0.1:1234", "http://127.0.0.1:50051", true},
		{"local development ui", "127.0.0.1:1234", "http://localhost:5173", true},
		{"official hosted ui", "127.0.0.1:1234", officialGatewayUIOrigin, true},
		{"official hosted ui ipv6", "[::1]:1234", officialGatewayUIOrigin, true},
		{"remote peer with no origin", "192.0.2.1:1234", "", false},
		{"remote peer with official origin", "192.0.2.1:1234", officialGatewayUIOrigin, false},
		{"remote peer with local origin", "192.0.2.1:1234", "http://localhost:50051", false},
		{"untrusted remote origin", "127.0.0.1:1234", "https://untrusted.example", false},
		{"other github pages site", "127.0.0.1:1234", "https://other.github.io", false},
		{"origin suffix confusion", "127.0.0.1:1234", "https://yuhaiin.github.io.evil.example", false},
		{"origin prefix confusion", "127.0.0.1:1234", "https://yuhaiin.github.io@evil.example", false},
		{"hosted ui over http", "127.0.0.1:1234", "http://yuhaiin.github.io", false},
		{"hosted ui extra port", "127.0.0.1:1234", "https://yuhaiin.github.io:444", false},
		{"local origin with path", "127.0.0.1:1234", "http://localhost:50051/admin", false},
		{"local origin invalid scheme", "127.0.0.1:1234", "file://localhost", false},
		{"opaque origin", "127.0.0.1:1234", "null", false},
	}

	// RPC transport uses POST for reads (workspace.get) as well as writes.
	// Both must remain available to the official hosted UI on loopback.
	for _, pattern := range []string{
		"POST /api/v2/rpc/gateway.workspace.get",
		"POST /api/v2/rpc/gateway.workspace.save",
		"POST /api/v2/rpc/gateway.ca.import",
	} {
		t.Run(pattern, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					called := false
					handler := guardGatewayManagement(nil, pattern, func(w http.ResponseWriter, _ *http.Request) error {
						called = true
						w.WriteHeader(http.StatusOK)
						return nil
					})
					request := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/gateway.workspace.get", nil)
					request.RemoteAddr = test.peer
					if test.origin != "" {
						request.Header.Set("Origin", test.origin)
					}
					response := httptest.NewRecorder()
					if err := handler(response, request); err != nil {
						t.Fatal(err)
					}
					if called != test.allowed {
						t.Fatalf("allowed=%v status=%d, want allowed=%v", called, response.Code, test.allowed)
					}
					wantStatus := http.StatusForbidden
					if test.allowed {
						wantStatus = http.StatusOK
					}
					if response.Code != wantStatus {
						t.Fatalf("status=%d want %d", response.Code, wantStatus)
					}
				})
			}
		})
	}
}
