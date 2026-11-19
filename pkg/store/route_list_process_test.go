package store

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestRouteListStoreValidatesProcessPatterns(t *testing.T) {
	ctx := t.Context()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store := NewRouteListStore(db.DB())

	entries := []string{"/usr/bin/curl", "/Applications/ExampleEditor.app/**", "**/aaa/**", `C:\Program Files\ExampleEditor\**`, "# comment", "com.example.app"}
	valid := contractroute.RouteListDetail{ID: "apps", Name: "Apps", Type: "process",
		Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: entries}}}
	if err := store.SaveRouteList(ctx, valid, 0); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetRouteList(ctx, "apps")
	if err != nil {
		t.Fatal(err)
	}
	// Patterns are stored exactly as written; the format is unchanged.
	if !slices.Equal(got.Source.Local.Lists, entries) {
		t.Fatalf("stored %v", got.Source.Local.Lists)
	}

	invalid := got
	invalid.Source.Local = &contractroute.LocalSource{Lists: []string{"/usr/bin/curl", "foo**bar", "", "chrome*"}}
	err = store.SaveRouteList(ctx, invalid, 0)
	if err == nil {
		t.Fatal("invalid process patterns were saved")
	}
	for _, want := range []string{`process list "Apps" (apps)`, `line 2: invalid process pattern "foo**bar"`, `line 4: invalid process pattern "chrome*"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if got, _ := store.GetRouteList(ctx, "apps"); !slices.Equal(got.Source.Local.Lists, entries) {
		t.Fatalf("rejected save changed the list: %v", got.Source.Local.Lists)
	}

	// Host lists are not process patterns.
	host := contractroute.RouteListDetail{ID: "hosts", Name: "hosts", Type: "host",
		Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"*.example.com"}}}}
	if err := store.SaveRouteList(ctx, host, 0); err != nil {
		t.Fatal(err)
	}
}
