package resolver

import (
	"errors"
	"iter"
	"slices"
	"sync"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type testHostLists struct {
	mu    sync.Mutex
	lists map[string][]string
}

func (s *testHostLists) HostListValues(id string) (iter.Seq[string], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	values, ok := s.lists[id]
	if !ok {
		return nil, errors.New("missing")
	}
	return slices.Values(slices.Clone(values)), nil
}

func (s *testHostLists) set(id string, values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists[id] = values
}

// useTestLists gives f in-memory shared lists, keyed by list ID.
func useTestLists(f *Fakedns, lists map[string][]string) *testHostLists {
	source := &testHostLists{lists: lists}
	f.SetHostListSource(source)
	return source
}

func TestFakednsSharedLists(t *testing.T) {
	f, err := NewFakeDNS(
		netapi.NewErrProxy(errors.New("test dialer")),
		netapi.ErrorResolver(func(string) error { return nil }),
		t.TempDir()+"/state.db",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	source := useTestLists(f, map[string][]string{
		"vpn":   {"*.tailscale.com", "10.0.0.0/8", "192.168.1.1"},
		"other": {"inline.example"},
		"skip":  {"time.apple.com"},
	})
	if err := f.Apply(contractresolver.FakeDNS{
		WhitelistListIDs: []string{"vpn", "other", "gone"},
		SkipCheckListIDs: []string{"skip"},
	}); err != nil {
		t.Fatal(err)
	}

	has := func(name string, whitelist bool) bool {
		f.fakeMu.RLock()
		defer f.fakeMu.RUnlock()
		trie := f.skipCheck
		if whitelist {
			trie = f.whitelist
		}
		_, ok := trie.SearchString(name)
		return ok
	}
	for _, name := range []string{"inline.example", "login.tailscale.com"} {
		if !has(name, true) {
			t.Errorf("whitelist misses %s", name)
		}
	}
	if !has("time.apple.com", false) || has("time.apple.com", true) {
		t.Error("skip check list was not built from its own list")
	}

	source.set("vpn", "*.oray.com")
	f.RefreshHostLists()
	if has("login.tailscale.com", true) || !has("a.oray.com", true) || !has("inline.example", true) {
		t.Error("refresh did not rebuild the whitelist from the updated list")
	}
}
