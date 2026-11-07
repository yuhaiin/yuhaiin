package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// A resource the current schema cannot use (here a removed protocol) is
// reported to the caller instead of aborting recovery. Corrupt storage still
// aborts: a document that is not a JSON object, or whose identity or activation state
// disagrees with its row.
func TestRecoveryWalkReportsUnsupportedResources(t *testing.T) {
	const (
		nodeInsert = `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json)
			VALUES (?, ?, 'manual', 'manual', ?, '[]', 1, ?)`
		inboundInsert = `INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,updated_at,data_json)
			VALUES (?, ?, ?, 'empty', 'none', '[]', 1, ?)`
		validNode      = `{"id":"a-valid","name":"a","origin":"manual","enabled":true,"chain":[{"type":"direct","direct":{}}]}`
		removedNode    = `{"id":"m-removed","name":"m","origin":"manual","enabled":true,"chain":[{"type":"http_termination","http_termination":{"cert_file_path":"legacy.pem"}}]}`
		validInbound   = `{"id":"a-valid","name":"a","enabled":true,"network":{"type":"empty","empty":{}},"protocol":{"type":"none","none":{}}}`
		removedInbound = `{"id":"m-removed","name":"m","enabled":true,"network":{"type":"empty","empty":{}},"protocol":{"type":"reverse_http"}}`
	)
	type row struct {
		id      string
		enabled bool
		data    string
	}
	walk := func(t *testing.T, insert string, rows []row, recover func(context.Context, *NodeStore, *InboundStore, func(UnsupportedResource) error) ([]string, error), unsupported bool) ([]string, []UnsupportedResource, error) {
		t.Helper()
		db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		for _, item := range rows {
			if _, err := db.DB().ExecContext(t.Context(), insert, item.id, item.id, item.enabled, item.data); err != nil {
				t.Fatal(err)
			}
		}
		var reported []UnsupportedResource
		var handler func(UnsupportedResource) error
		if unsupported {
			handler = func(resource UnsupportedResource) error { reported = append(reported, resource); return nil }
		}
		visited, err := recover(t.Context(), NewNodeStore(db.DB()), NewInboundStore(db.DB()), handler)
		return visited, reported, err
	}
	nodes := func(ctx context.Context, nodes *NodeStore, _ *InboundStore, unsupported func(UnsupportedResource) error) ([]string, error) {
		var ids []string
		err := nodes.RangeForRecovery(ctx, func(node contractnode.Node) error { ids = append(ids, node.ID); return nil }, unsupported)
		return ids, err
	}
	inbounds := func(ctx context.Context, _ *NodeStore, inbounds *InboundStore, unsupported func(UnsupportedResource) error) ([]string, error) {
		var ids []string
		err := inbounds.RangeForRecovery(ctx, func(inbound contractinbound.Inbound) error { ids = append(ids, inbound.ID); return nil }, unsupported)
		return ids, err
	}
	for _, test := range []struct {
		name, insert, valid, removed string
		recover                      func(context.Context, *NodeStore, *InboundStore, func(UnsupportedResource) error) ([]string, error)
	}{
		{"nodes", nodeInsert, validNode, removedNode, nodes},
		{"inbounds", inboundInsert, validInbound, removedInbound, inbounds},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows := []row{{"a-valid", true, test.valid}, {"m-removed", true, test.removed}}
			visited, reported, err := walk(t, test.insert, rows, test.recover, true)
			if err != nil || !slices.Equal(visited, []string{"a-valid"}) || len(reported) != 1 {
				t.Fatalf("unsupported resource blocked recovery: visited %v, reported %v, err %v", visited, reported, err)
			}
			if reported[0].ID != "m-removed" || reported[0].Err == nil {
				t.Fatalf("unsupported resource reported without identity or cause: %+v", reported[0])
			}
			if document, ok := reported[0].Document.(map[string]any); !ok || document["id"] != "m-removed" {
				t.Fatalf("raw document not preserved: %#v", reported[0].Document)
			}
			if _, _, err := walk(t, test.insert, rows, test.recover, false); err == nil {
				t.Fatal("unsupported resource accepted without a handler")
			}
			for name, corrupt := range map[string]row{
				"not an object":    {"m-removed", true, `[1]`},
				"identity":         {"m-removed", true, `{"id":"other"` + test.valid[len(`{"id":"a-valid"`):]},
				"activation state": {"m-removed", false, `{"id":"m-removed"` + test.valid[len(`{"id":"a-valid"`):]},
			} {
				if _, reported, err := walk(t, test.insert, []row{corrupt}, test.recover, true); err == nil || len(reported) != 0 {
					t.Fatalf("%s corruption reported as unsupported: %v, %v", name, reported, err)
				}
			}
		})
	}
}
