package resolver

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestHostEntryChangesPersistAndActivateTogether(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	raw := plainstore.NewResolverConfigStore(db.DB())
	hosts := NewHosts(nil, nil)
	controller := NewContractConfigController(&ResolverCtr{config: raw, hosts: hosts})
	facade := plainstore.NewResolverConfigRuntimeStore(raw, controller)
	if _, err := facade.SaveHosts(t.Context(), contractresolver.Hosts{Hosts: map[string]string{"existing.example": "192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			entry := contractresolver.HostEntry{Host: fmt.Sprintf("new-%02d.example", i), Target: "192.0.2.2"}
			if _, err := facade.SaveHostEntry(t.Context(), entry, true); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	snapshot, err := raw.Hosts(t.Context())
	if err != nil || len(snapshot.Hosts) != 13 {
		t.Fatalf("snapshot = %+v, %v", snapshot, err)
	}
	check := func(host, target string) {
		t.Helper()
		addr, err := netapi.ParseAddress("tcp", host+":443")
		if err != nil {
			t.Fatal(err)
		}
		got := hosts.dispatchAddr(t.Context(), addr)
		if got.Hostname() != target {
			t.Fatalf("runtime %s = %s, want %s", host, got.Hostname(), target)
		}
	}
	check("existing.example", "192.0.2.1")
	for i := range 12 {
		check(fmt.Sprintf("new-%02d.example", i), "192.0.2.2")
	}
	if _, err := facade.SaveHostEntry(t.Context(), contractresolver.HostEntry{Host: "new-00.example", Target: "alias.example"}, false); err != nil {
		t.Fatal(err)
	}
	check("new-00.example", "alias.example")
	if err := facade.DeleteHostEntry(t.Context(), "new-00.example"); err != nil {
		t.Fatal(err)
	}
	check("new-00.example", "new-00.example")
	portEntry := contractresolver.HostEntry{Host: "ports.example:443", Target: "192.0.2.3:8443"}
	if _, err := facade.SaveHostEntry(t.Context(), portEntry, true); err != nil {
		t.Fatal(err)
	}
	address, err := netapi.ParseAddress("tcp", portEntry.Host)
	if err != nil {
		t.Fatal(err)
	}
	redirected := hosts.dispatchAddr(t.Context(), address)
	if redirected.Hostname() != "192.0.2.3" || redirected.Port() != 8443 {
		t.Fatalf("port mapping = %s", redirected)
	}
	if err := facade.DeleteHostEntry(t.Context(), portEntry.Host); err != nil {
		t.Fatal(err)
	}
	if got := hosts.dispatchAddr(t.Context(), address); got.Hostname() != "ports.example" || got.Port() != 443 {
		t.Fatalf("removed port mapping = %s", got)
	}

}
