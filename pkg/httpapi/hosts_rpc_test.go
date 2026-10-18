package httpapi

import (
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestHostEntriesRPC(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	config := plainstore.NewResolverConfigStore(db.DB())
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) })
	}, V2Services{ResolverConfig: config})
	rpc := func(method, body string, status int) string {
		t.Helper()
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/"+method, strings.NewReader(body)))
		if response.Code != status {
			t.Fatalf("%s = %d %s", method, response.Code, response.Body.String())
		}
		return response.Body.String()
	}
	for i := range 35 {
		rpc("resolver.hosts.entry.post", fmt.Sprintf(`{"host":"host-%02d.example","target":"192.0.2.1"}`, i), http.StatusOK)
	}
	var page listV2[contractresolver.HostEntry]
	if err := json.Unmarshal([]byte(rpc("resolver.hosts.entries", `{"page":2,"page_size":20}`, http.StatusOK)), &page); err != nil {
		t.Fatal(err)
	}
	if page.Page.Total != 35 || page.Page.PageSize != 20 || len(page.Items) != 15 || page.Items[0].Host != "host-20.example" {
		t.Fatalf("page = %+v", page)
	}
	rpc("resolver.hosts.entry.post", `{"host":"host-00.example","target":"192.0.2.99"}`, http.StatusConflict)
	rpc("resolver.hosts.entry.put", `{"host":"host-00.example","target":"alias.example"}`, http.StatusOK)
	if result := rpc("resolver.hosts.entry.get", `{"host":"host-00.example"}`, http.StatusOK); !strings.Contains(result, `"target":"alias.example"`) {
		t.Fatal(result)
	}
	rpc("resolver.hosts.entry.delete", `{"host":"host-00.example"}`, http.StatusOK)
	rpc("resolver.hosts.entry.get", `{"host":"host-00.example"}`, http.StatusNotFound)
	rpc("resolver.hosts.entry.put", `{"host":"absent.example","target":"192.0.2.1"}`, http.StatusNotFound)
	rpc("resolver.hosts.entry.post", `{"host":"https://example.com","target":"192.0.2.1"}`, http.StatusBadRequest)
}
