package store

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestFakeDNSSharedListReferences(t *testing.T) {
	ctx := t.Context()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()
	lists := NewRouteListStore(sqliteStore.DB())
	config := NewResolverConfigStore(sqliteStore.DB())

	save := func(name, listType string) string {
		t.Helper()
		detail := contractroute.RouteListDetail{
			Name:   name,
			Type:   listType,
			Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"example.com"}}},
		}
		if err := lists.SaveRouteList(ctx, detail, 1); err != nil {
			t.Fatal(err)
		}
		got, err := lists.GetRouteList(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		return got.ID
	}
	hostID := save("vpn-hosts", "host")
	processID := save("apps", "process")

	want := contractresolver.FakeDNS{
		WhitelistListIDs: []string{hostID},
		SkipCheckListIDs: []string{hostID},
	}
	if _, err := config.SaveFakeDNS(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := config.FakeDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fakedns = %+v, want %+v", got, want)
	}

	var inUse *ResourceInUseError
	if err := lists.DeleteRouteList(ctx, hostID); !errors.As(err, &inUse) || len(inUse.References) != 2 {
		t.Fatalf("delete referenced list error = %v", err)
	}

	if _, err := config.SaveFakeDNS(ctx, contractresolver.FakeDNS{WhitelistListIDs: []string{processID}}); err == nil {
		t.Fatal("saving a process list reference succeeded")
	}
	if _, err := config.SaveFakeDNS(ctx, contractresolver.FakeDNS{SkipCheckListIDs: []string{"missing"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("saving a missing list reference error = %v", err)
	}
	if got, err := config.FakeDNS(ctx); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("rejected save changed settings: %+v, %v", got, err)
	}

	// A client that omits the reference fields keeps them.
	if got, err := config.SaveFakeDNS(ctx, contractresolver.FakeDNS{Enabled: true}); err != nil || !reflect.DeepEqual(got.WhitelistListIDs, want.WhitelistListIDs) || !reflect.DeepEqual(got.SkipCheckListIDs, want.SkipCheckListIDs) {
		t.Fatalf("save without reference fields = %+v, %v", got, err)
	}
	if _, err := config.SaveFakeDNS(ctx, contractresolver.FakeDNS{WhitelistListIDs: []string{}, SkipCheckListIDs: []string{}}); err != nil {
		t.Fatal(err)
	}
	if err := lists.DeleteRouteList(ctx, hostID); err != nil {
		t.Fatalf("delete unreferenced list: %v", err)
	}
}
