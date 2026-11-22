package store

import (
	json "encoding/json/v2"
	"path/filepath"
	"testing"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestSubscriptionStoreSaveListDeleteLinks(t *testing.T) {
	ctx := t.Context()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewSubscriptionStore(sqliteStore.DB())
	if err := store.SaveLinks(ctx, []contractsubscription.Link{{
		Name: "remote",
		URL:  "https://example.com/sub",
		Type: "trojan",
	}}, 123); err != nil {
		t.Fatal(err)
	}

	got, err := store.ListLinks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Name != "remote" || got.Items[0].Type != "trojan" {
		t.Fatalf("links = %+v", got)
	}

	var dataJSON string
	if err := sqliteStore.DB().QueryRowContext(ctx, `SELECT data_json FROM subscriptions WHERE name = 'remote'`).Scan(&dataJSON); err != nil {
		t.Fatal(err)
	}
	var stored contractsubscription.Link
	if err := jsonUnmarshalContract(dataJSON, &stored); err != nil {
		t.Fatalf("link decode failed: %v; json=%s", err, dataJSON)
	}
	if stored.Type != "trojan" {
		t.Fatalf("stored link type = %s", stored.Type)
	}

	if err := store.DeleteLinks(ctx, []string{"remote"}); err != nil {
		t.Fatal(err)
	}
	got, err = store.ListLinks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 0 {
		t.Fatalf("links after delete = %+v", got)
	}
}

func jsonUnmarshalContract(data string, out any) error {
	return json.Unmarshal([]byte(data), out)
}
