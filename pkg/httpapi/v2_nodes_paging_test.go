package httpapi

import (
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestV2NodePagingDoesNotReadOtherPagesOrGroups(t *testing.T) {
	db, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store := plainstore.NewNodeStore(db.DB())
	for index := range 101 {
		group := "manual"
		if index == 100 {
			group = "work"
		}
		node := contractnode.Node{ID: fmt.Sprintf("node-%03d", index), Name: fmt.Sprintf("Node%03d", index), Group: group, Origin: "manual", Enabled: index != 0,
			Chain: []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}}
		if err := store.Save(t.Context(), node, 0); err != nil {
			t.Fatal(err)
		}
	}
	// Invalid contract data on an unrequested page makes an eager full read fail.
	if _, err := db.DB().ExecContext(t.Context(), `UPDATE nodes_v2 SET data_json = '{"id":5}' WHERE id = 'node-100'`); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if err := handler(w, r); err != nil {
				t.Fatal(err)
			}
		})
	}, V2Services{Nodes: store})
	call := func(operation, payload string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/"+operation, strings.NewReader(payload)))
		return recorder
	}
	groups := call("nodes.groups", `{}`)
	if groups.Code != http.StatusOK || !strings.Contains(groups.Body.String(), `"count":100`) {
		t.Fatalf("group metadata: %d %s", groups.Code, groups.Body.String())
	}
	for _, test := range []struct {
		name, payload string
		items, total  int
	}{
		{"bounded default", `{}`, 100, 101},
		{"first global page", `{"page":1,"page_size":1}`, 1, 101},
		{"group page", `{"group":"manual","page":2,"page_size":40}`, 40, 100},
		{"enabled group", `{"group":"manual","enabled_only":true,"page_size":40}`, 40, 99},
		{"server search", `{"group":"manual","query":"Node099","page_size":40}`, 1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := call("nodes.get", test.payload)
			if response.Code != http.StatusOK {
				t.Fatalf("nodes: %d %s", response.Code, response.Body.String())
			}
			var result listV2[contractnode.Node]
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Items) != test.items || result.Page.Total != test.total {
				t.Fatalf("page: got %d items, %d total; want %d, %d", len(result.Items), result.Page.Total, test.items, test.total)
			}
		})
	}
}
