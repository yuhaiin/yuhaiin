package route

import (
	"context"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type listSettingsStub struct {
	value RouteListSettings
}

func (s *listSettingsStub) ListSettings(context.Context) (RouteListSettings, error) {
	return s.value, nil
}

func (s *listSettingsStub) SaveListSettings(_ context.Context, value RouteListSettings) error {
	s.value = value
	return nil
}

func TestHostIndexUpdateKeepsPreviousTrieReadableUntilSwap(t *testing.T) {
	oldDataDir := configuration.DataDir.Load()
	dataDir := t.TempDir()
	configuration.DataDir.Store(dataDir)
	t.Cleanup(func() { configuration.DataDir.Store(oldDataDir) })

	lists := &Lists{hostTrie: newHostTrie(dataDir, true)}
	lists.hostTrieDisk.Store(true)
	t.Cleanup(func() {
		if err := lists.Close(); err != nil {
			t.Logf("close lists failed: %v", err)
		}
	})
	if err := lists.hostTrie.Add(func(yield func(string) bool) {
		yield("old.example.com")
	}, "old"); err != nil {
		t.Fatal(err)
	}

	oldAddress, err := netapi.ParseAddressPort("", "old.example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	newAddress, err := netapi.ParseAddressPort("", "new.example.com", 0)
	if err != nil {
		t.Fatal(err)
	}

	building := make(chan struct{})
	continueBuild := make(chan struct{})
	updated := make(chan struct{})
	release := sync.OnceFunc(func() { close(continueBuild) })
	defer release()
	go func() {
		lists.updateHostLists(func() {
			for range 3 {
				if err := lists.hostTrieBuild.Add(func(yield func(string) bool) { yield("new.example.com") }, "new"); err != nil {
					t.Errorf("add new host list: %v", err)
				}
				if err := lists.hostTrieBuild.Sync(); err != nil {
					t.Errorf("sync new host list: %v", err)
				}
			}
			close(building)
			<-continueBuild
		})
		close(updated)
	}()

	<-building
	if got := lists.SearchHost(t.Context(), oldAddress); !slices.Contains(got, "old") {
		t.Fatalf("old index during rebuild = %v, want old list", got)
	}
	release()
	<-updated
	if got := lists.SearchHost(t.Context(), oldAddress); len(got) != 0 {
		t.Fatalf("old index after swap = %v, want no matches", got)
	}
	if got := lists.SearchHost(t.Context(), newAddress); !slices.Contains(got, "new") {
		t.Fatalf("new index after swap = %v, want new list", got)
	}
	segments, err := filepath.Glob(filepath.Join(lists.hostTrie.cache.Dir(), "segment-*.mmap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) != 1 {
		t.Fatalf("completed update has %d domain segments, want 1", len(segments))
	}
}

func TestRefreshGeoIPSkipsEmptyURL(t *testing.T) {
	lists := &Lists{downloader: NewDownloader(t.TempDir(), nil)}
	if err := lists.refreshGeoip(t.Context(), "", true); err != "" {
		t.Fatalf("refreshGeoip(empty) = %q", err)
	}
}
