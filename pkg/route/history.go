package route

import (
	"context"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/schema/api"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

type blockHistoryKey struct {
	protocol string
	host     string
	process  string
}

type blockHistoryEntry struct {
	*api.BlockHistory
	mu sync.Mutex
}

type RejectHistory struct {
	store *lru.SyncLru[blockHistoryKey, *blockHistoryEntry]
}

func NewRejectHistory() *RejectHistory {
	return &RejectHistory{
		store: lru.NewSyncLru(lru.WithCapacity[blockHistoryKey, *blockHistoryEntry](int(configuration.HistorySize))),
	}
}

func (h *RejectHistory) Push(ctx context.Context, protocol string, host string) {
	store := netapi.GetContext(ctx)

	key := blockHistoryKey{protocol, host, store.GetProcessName()}
	x, ok := h.store.LoadOrAdd(key, func() *blockHistoryEntry {
		return &blockHistoryEntry{
			BlockHistory: (&api.BlockHistory_builder{
				Protocol:   new(protocol),
				Host:       new(host),
				Time:       time.Now(),
				Process:    new(store.GetProcessName()),
				BlockCount: uint64Ptr(1),
			}).Build(),
		}
	})
	if !ok {
		return
	}

	x.mu.Lock()
	x.SetTime(time.Now())
	x.SetBlockCount(x.GetBlockCount() + 1)
	x.mu.Unlock()
}

func uint64Ptr(v uint64) *uint64 { return &v }

func (h *RejectHistory) Get() *api.BlockHistoryList {
	var objects []*api.BlockHistory
	dumpProcess := false
	for _, v := range h.store.Range {
		objects = append(objects, v.BlockHistory)
		if !dumpProcess && v.GetProcess() != "" {
			dumpProcess = true
		}
	}
	return api.BlockHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: new(dumpProcess),
	}.Build()
}
