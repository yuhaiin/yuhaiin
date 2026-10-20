package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRequestTracePreservesHost(t *testing.T) {
	for _, tc := range []struct {
		name       string
		protoMajor int
		host       string
	}{
		{name: "http1_with_port", protoMajor: 1, host: "example.com:8443"},
		{name: "http2_authority", protoMajor: 2, host: "h2.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://original.example/path", nil)
			r.ProtoMajor = tc.protoMajor
			r.Host = tc.host

			trace := newRequestTrace("gateway-id", "gateway", httptest.NewRecorder(), r)
			// Log the original HTTP authority even if forwarding rewrites the host.
			r.Host = "backend.internal"
			if trace.host != tc.host {
				t.Fatalf("trace host = %q, want %q", trace.host, tc.host)
			}
		})
	}
}
