package route

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type hostTrie struct {
	lists *set.Set[string]
	trie  *trie.Trie[string]
}

func newHostTrie() *hostTrie {
	return &hostTrie{
		lists: set.NewSet[string](),
		trie:  trie.NewTrie[string](),
	}
}

func (h *hostTrie) Add(host string, list string) {
	h.lists.Push(list)
	h.trie.Insert(host, list)
}

func (h *hostTrie) Search(ctx context.Context, addr netapi.Address) *set.Set[string] {
	return h.trie.Search(ctx, addr)
}

func (h *hostTrie) Include(list string) bool {
	return h.lists.Has(list)
}

type processTrie struct {
	lists *set.Set[string]

	trie syncmap.SyncMap[string, *set.Set[string]]
}

func newProcessTrie() *processTrie {
	return &processTrie{
		lists: set.NewSet[string](),
	}
}

func (h *processTrie) Add(process string, list string) {
	h.lists.Push(list)

	set, _, _ := h.trie.LoadOrCreate(process, func() (*set.Set[string], error) {
		return set.NewSet[string](), nil
	})

	set.Push(list)
}

func (h *processTrie) Include(list string) bool {
	return h.lists.Has(list)
}

func (h *processTrie) Search(ctx context.Context, addr netapi.Address) *set.Set[string] {
	store := netapi.GetContext(ctx)
	process := store.GetProcessName()
	s, ok := h.trie.Load(process)
	if !ok {
		return set.NewSet[string]()
	}
	return s
}
