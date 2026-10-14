package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolverDiagnosticRPC(t *testing.T) {
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) })
	}, V2Services{})
	for _, test := range []struct {
		name, method, body string
		status             int
		contains           string
	}{
		{"library types", "resolver.query_types", `{}`, http.StatusOK, `"HTTPS"`},
		{"invalid domain", "resolver.test", `{"resolver":{"type":"udp","host":"127.0.0.1:53"},"domain":"https://example.com","queryType":"A"}`, http.StatusBadRequest, `invalid DNS query domain`},
		{"zone transfer", "resolver.test", `{"resolver":{"type":"udp","host":"127.0.0.1:53"},"domain":"example.com","queryType":"AXFR"}`, http.StatusBadRequest, `unsupported DNS query type`},
		{"no controller", "resolver.test", `{"resolver":{"type":"udp","host":"127.0.0.1:53"},"domain":"example.com","queryType":"A"}`, http.StatusServiceUnavailable, `unavailable`},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/"+test.method, strings.NewReader(test.body)))
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}
