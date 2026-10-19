package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestIndependentConfigListsSkipInvalidStoredRecords(t *testing.T) {
	for _, test := range []struct {
		name, insert, valid, invalid string
		list                         func(context.Context, *sql.DB) ([]string, error)
	}{
		{
			name: "inbounds",
			insert: `INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,updated_at,data_json)
				VALUES (?, ?, 1, 'empty', 'none', '[]', 1, ?)`,
			valid:   `{"id":%q,"name":%q,"network":{"type":"empty","empty":{}},"protocol":{"type":"none","none":{}}}`,
			invalid: `{"id":"m-invalid","network":{"type":"empty","empty":{}},"protocol":{"type":"reverse_http"}}`,
			list: func(ctx context.Context, db *sql.DB) ([]string, error) {
				items, err := NewInboundStore(db).List(ctx)
				ids := []string{}
				for _, item := range items {
					ids = append(ids, item.ID)
				}
				return ids, err
			},
		},
		{
			name: "nodes",
			insert: `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json)
				VALUES (?, ?, 'manual', 'manual', 1, '[]', 1, ?)`,
			valid:   `{"id":%q,"name":%q,"group":"manual","origin":"manual","enabled":true,"chain":[{"type":"direct","direct":{}}]}`,
			invalid: `{"id":"m-invalid","name":"invalid","origin":"manual","chain":[{"type":"http_termination"}]}`,
			list: func(ctx context.Context, db *sql.DB) ([]string, error) {
				items, err := NewNodeStore(db).List(ctx)
				ids := []string{}
				for _, item := range items {
					ids = append(ids, item.ID)
				}
				return ids, err
			},
		},
		{
			name: "node page",
			insert: `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json)
				VALUES (?, ?, 'manual', 'manual', 1, '[]', 1, ?)`,
			valid:   `{"id":%q,"name":%q,"group":"manual","origin":"manual","enabled":true,"chain":[{"type":"direct","direct":{}}]}`,
			invalid: `{"id":"m-invalid","name":"invalid","origin":"manual","chain":[{"type":"http_termination"}]}`,
			list: func(ctx context.Context, db *sql.DB) ([]string, error) {
				items, total, err := NewNodeStore(db).ListPage(ctx, "manual", "", false, 1, 100)
				if err == nil && total != 3 {
					return nil, fmt.Errorf("persisted row count = %d, want 3", total)
				}
				ids := []string{}
				for _, item := range items {
					ids = append(ids, item.ID)
				}
				return ids, err
			},
		},
		{
			name:    "resolvers",
			insert:  `INSERT INTO resolvers_v2(id,resolver_type,host,updated_at,data_json) VALUES (?, 'udp', ?, 1, ?)`,
			valid:   `{"id":%q,"name":%q,"type":"udp","host":"127.0.0.1:53"}`,
			invalid: `{"id":"m-invalid","type":"unsupported","host":"127.0.0.1:53"}`,
			list: func(ctx context.Context, db *sql.DB) ([]string, error) {
				items, err := NewResolverStore(db).List(ctx)
				ids := []string{}
				for _, item := range items {
					ids = append(ids, item.ID)
				}
				return ids, err
			},
		},
		{
			name:    "subscriptions",
			insert:  `INSERT INTO subscriptions(name,updated_at,data_json) VALUES (?, ?, ?)`,
			valid:   `{"name":%q,"url":%q,"type":"reserve"}`,
			invalid: `{"name":"m-invalid","url":""}`,
			list: func(ctx context.Context, db *sql.DB) ([]string, error) {
				items, err := NewSubscriptionStore(db).ListLinks(ctx)
				ids := []string{}
				for _, item := range items.Items {
					ids = append(ids, item.Name)
				}
				return ids, err
			},
		},
		{
			name:    "publishes",
			insert:  `INSERT INTO publishes(name,updated_at,data_json) VALUES (?, ?, ?)`,
			valid:   `{"name":%q,"address":%q,"points":[]}`,
			invalid: `{"name":42}`,
			list: func(ctx context.Context, db *sql.DB) ([]string, error) {
				items, err := NewSubscriptionStore(db).ListPublishes(ctx)
				ids := []string{}
				for _, item := range items.Items {
					ids = append(ids, item.Name)
				}
				return ids, err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			for _, id := range []string{"a-valid", "m-invalid", "z-valid"} {
				data := fmt.Sprintf(test.valid, id, id)
				if id == "m-invalid" {
					data = test.invalid
				}
				var second any = id
				if test.name == "subscriptions" || test.name == "publishes" {
					second = 1
				}
				if _, err := db.DB().ExecContext(ctx, test.insert, id, second, data); err != nil {
					t.Fatal(err)
				}
			}
			items, err := test.list(ctx, db.DB())
			want := []string{"a-valid", "z-valid"}
			if test.name == "inbounds" {
				// Inbound runtime status reports compatibility failures, so keep
				// their saved entries visible for inspection and removal.
				want = []string{"a-valid", "m-invalid", "z-valid"}
			}
			if err != nil || !slices.Equal(items, want) {
				t.Fatalf("one invalid record prevented valid records from loading: %v, %v", items, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := test.list(ctx, db.DB()); err == nil {
				t.Fatal("database failure was swallowed")
			}
		})
	}
}
