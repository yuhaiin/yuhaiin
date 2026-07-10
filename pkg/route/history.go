package route

import (
	"context"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

type blockHistoryKey struct {
	protocol string
	host     string
	process  string
}

type blockHistoryEntry struct {
	item  contractroute.BlockHistory
	count uint64
	mu    sync.Mutex
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
			count: 1,
			item: contractroute.BlockHistory{
				Protocol: protocol,
				Host:     host,
				Time:     time.Now(),
				Process:  store.GetProcessName(),
			},
		}
	})
	if !ok {
		return
	}

	x.mu.Lock()
	x.item.Time = time.Now()
	x.count++
	x.mu.Unlock()
}

func (h *RejectHistory) Get() contractroute.BlockHistoryList {
	var objects []contractroute.BlockHistory
	dumpProcess := false
	for _, v := range h.store.Range {
		v.mu.Lock()
		item := v.item
		item.BlockCount = formatUint64(v.count)
		v.mu.Unlock()
		objects = append(objects, item)
		if !dumpProcess && item.Process != "" {
			dumpProcess = true
		}
	}
	return contractroute.BlockHistoryList{
		Items:              objects,
		DumpProcessEnabled: dumpProcess,
	}
}
