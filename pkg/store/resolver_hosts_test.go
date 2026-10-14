package store

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestHostEntriesArePagedAndIndependentlyUpdated(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewResolverConfigStore(db.DB())
	hosts := map[string]string{}
	for i := range 260 {
		hosts[fmt.Sprintf("host-%03d.example", i)] = "192.0.2.1"
	}
	hosts["literal%host.example"] = "alias.example:443"
	if _, err := store.SaveHosts(t.Context(), contractresolver.Hosts{Hosts: hosts}); err != nil {
		t.Fatal(err)
	}
	items, total, err := store.ListHostEntries(t.Context(), 2, 20, "")
	if err != nil || total != 261 || len(items) != 20 || items[0].Host != "host-020.example" {
		t.Fatalf("page = %+v total=%d err=%v", items, total, err)
	}
	items, _, err = store.ListHostEntries(t.Context(), 1, 9999, "")
	if err != nil || len(items) != 100 {
		t.Fatalf("bounded page length=%d err=%v", len(items), err)
	}
	items, _, err = store.ListHostEntries(t.Context(), 1, 0, "")
	if err != nil || len(items) != 25 {
		t.Fatalf("default page length=%d err=%v", len(items), err)
	}
	items, total, err = store.ListHostEntries(t.Context(), 1, 20, "%")
	if err != nil || total != 1 || len(items) != 1 || items[0].Host != "literal%host.example" {
		t.Fatalf("literal search = %+v total=%d err=%v", items, total, err)
	}
	items, total, err = store.ListHostEntries(t.Context(), 1, 20, "ALIAS.EXAMPLE")
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("target search=%+v total=%d err=%v", items, total, err)
	}
	items, total, err = store.ListHostEntries(t.Context(), math.MaxInt, 20, "")
	if err != nil || total != 261 || len(items) != 0 {
		t.Fatalf("huge page length=%d total=%d err=%v", len(items), total, err)
	}
	entry := contractresolver.HostEntry{Host: "host-000.example", Target: "192.0.2.9"}
	if _, err := store.SaveHostEntry(t.Context(), entry, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveHostEntry(t.Context(), entry, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create = %v", err)
	}
	if err := store.DeleteHostEntry(t.Context(), "host-100.example"); err != nil {
		t.Fatal(err)
	}
	unchanged, err := store.HostEntry(t.Context(), "host-259.example")
	if err != nil || unchanged.Target != "192.0.2.1" {
		t.Fatalf("unrequested entry = %+v %v", unchanged, err)
	}
	saved, err := store.HostEntry(t.Context(), entry.Host)
	if err != nil || saved != entry {
		t.Fatalf("saved = %+v %v", saved, err)
	}
	if _, err := store.HostEntry(t.Context(), "host-100.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted get = %v", err)
	}
	if _, err := store.SaveHostEntry(t.Context(), contractresolver.HostEntry{Host: "absent.example", Target: "192.0.2.2"}, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing update = %v", err)
	}
	if err := store.DeleteHostEntry(t.Context(), "absent.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete = %v", err)
	}
}
