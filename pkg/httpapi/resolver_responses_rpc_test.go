package httpapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestResponseRulesRPC(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) })
	}, V2Services{ResolverConfig: store.NewResolverConfigStore(db.DB())})
	rpc := func(operation, body string, status int) string {
		t.Helper()
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/"+operation, strings.NewReader(body)))
		if w.Code != status {
			t.Fatalf("%s = %d %s", operation, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if result := rpc("resolver.responses.get", `{}`, http.StatusOK); !strings.Contains(result, `"rules":[]`) {
		t.Fatal(result)
	}
	config := `{"rules":[{"domain":"*.example.com","queryType":"HTTPS","rcode":"NXDOMAIN","ttl":0,"answers":[]},{"domain":"*.a.example.com","queryType":"AAAA","rcode":"NOERROR","ttl":300,"answers":["::1"]}]}`
	rpc("resolver.responses.put", config, http.StatusOK)
	rpc("resolver.responses.put", `{"rules":[{"domain":"*.example.com","queryType":"AAAA","rcode":"NOERROR","answers":["127.0.0.1"]}]}`, http.StatusBadRequest)
	if result := rpc("resolver.responses.get", `{}`, http.StatusOK); !strings.Contains(result, `"::1"`) || !strings.Contains(result, `"NXDOMAIN"`) {
		t.Fatal(result)
	}
	rpc("resolver.responses.put", `{"rules":[]}`, http.StatusOK)
	if result := rpc("resolver.responses.get", `{}`, http.StatusOK); !strings.Contains(result, `"rules":[]`) {
		t.Fatal(result)
	}
}
