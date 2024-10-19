package route

import (
	"context"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type blockHistoryKey struct {
	protocol string
	host     string
	process  string
}

type blockHistoryEntry struct {
	*gc.BlockHistory
	mu sync.Mutex
}

type RejectHistory struct {
	store       *lru.SyncLru[blockHistoryKey, *blockHistoryEntry]
	dumpProcess bool
}

func NewRejectHistory() *RejectHistory {
	return &RejectHistory{
		store: lru.NewSyncLru(lru.WithCapacity[blockHistoryKey, *blockHistoryEntry](1000)),
	}
}

func (h *RejectHistory) Push(ctx context.Context, protocol string, host string) {
	store := netapi.GetContext(ctx)

	if !h.dumpProcess && store.Process != "" {
		h.dumpProcess = true
	}

	key := blockHistoryKey{protocol, host, store.Process}
	x, ok := h.store.LoadOrAdd(key, func() *blockHistoryEntry {
		return &blockHistoryEntry{
			BlockHistory: &gc.BlockHistory{
				Protocol:   protocol,
				Host:       host,
				Time:       timestamppb.Now(),
				Process:    store.Process,
				BlockCount: 1,
			},
		}
	})
	if !ok {
		return
	}

	x.mu.Lock()
	x.Time = timestamppb.Now()
	x.BlockCount++
	x.mu.Unlock()
}

func (h *RejectHistory) Get() *gc.BlockHistoryList {
	var objects []*gc.BlockHistory
	for _, v := range h.store.Range {
		objects = append(objects, v.BlockHistory)
	}
	return &gc.BlockHistoryList{
		Objects:            objects,
		DumpProcessEnabled: h.dumpProcess,
	}
}
