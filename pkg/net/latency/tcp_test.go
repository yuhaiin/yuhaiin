package latency

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

func TestHTTPWithInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if _, err := HTTPWithInsecureSkipVerify(direct.Default, server.URL, false); err == nil {
		t.Fatal("HTTPS with an untrusted certificate succeeded while verification was enabled")
	}
	if _, err := HTTPWithInsecureSkipVerify(direct.Default, server.URL, true); err != nil {
		t.Fatalf("HTTPS with explicitly skipped verification failed: %v", err)
	}
}
