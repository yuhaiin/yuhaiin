package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnauthenticatedGatewayManagementIsLocalOnly(t *testing.T) {
	for _, test := range []struct {
		peer, origin string
		allowed      bool
	}{{"127.0.0.1:1234", "", true}, {"[::1]:1234", "http://localhost:50051", true}, {"192.0.2.1:1234", "", false}, {"127.0.0.1:1234", "https://untrusted.example", false}, {"127.0.0.1:1234", "null", false}} {
		t.Run(test.peer+test.origin, func(t *testing.T) {
			called := false
			handler := guardGatewayManagement(nil, "POST /api/v2/rpc/gateway.ca.import", func(w http.ResponseWriter, _ *http.Request) error {
				called = true
				w.WriteHeader(http.StatusOK)
				return nil
			})
			request := httptest.NewRequest("POST", "/api/v2/rpc/gateway.ca.import", nil)
			request.RemoteAddr = test.peer
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response := httptest.NewRecorder()
			if err := handler(response, request); err != nil {
				t.Fatal(err)
			}
			if called != test.allowed {
				t.Fatalf("allowed=%v status=%d", called, response.Code)
			}
		})
	}
}
