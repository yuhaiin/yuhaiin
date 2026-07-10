package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestResolverConfigStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewResolverConfigStore(sqliteStore.DB())

	hosts := contractresolver.Hosts{Hosts: map[string]string{
		"example.com": "1.1.1.1",
		"local.test":  "127.0.0.1",
	}}
	if _, err := store.SaveHosts(ctx, hosts); err != nil {
		t.Fatal(err)
	}
	gotHosts, err := store.Hosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotHosts, hosts) {
		t.Fatalf("hosts = %+v, want %+v", gotHosts, hosts)
	}

	fakedns := contractresolver.FakeDNS{
		Enabled:       true,
		IPv4Range:     "198.18.0.0/16",
		IPv6Range:     "fc00::/18",
		Whitelist:     []string{"allow.example"},
		SkipCheckList: []string{"skip.example"},
	}
	if _, err := store.SaveFakeDNS(ctx, fakedns); err != nil {
		t.Fatal(err)
	}
	gotFakeDNS, err := store.FakeDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotFakeDNS, fakedns) {
		t.Fatalf("fakedns = %+v, want %+v", gotFakeDNS, fakedns)
	}

	server := contractresolver.Server{Server: "223.5.5.5:53"}
	if _, err := store.SaveServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	gotServer, err := store.Server(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gotServer != server {
		t.Fatalf("server = %+v, want %+v", gotServer, server)
	}

	gotFakeDNS, err = store.FakeDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotFakeDNS, fakedns) {
		t.Fatalf("fakedns after server save = %+v, want %+v", gotFakeDNS, fakedns)
	}
}
