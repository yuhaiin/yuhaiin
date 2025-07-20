package route

import (
	"context"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"google.golang.org/protobuf/proto"
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
			BlockHistory: (&gc.BlockHistory_builder{
				Protocol:   proto.String(protocol),
				Host:       proto.String(host),
				Time:       timestamppb.Now(),
				Process:    proto.String(store.GetProcessName()),
				BlockCount: proto.Uint64(1),
			}).Build(),
		}
	})
	if !ok {
		return
	}

	x.mu.Lock()
	x.BlockHistory.SetTime(timestamppb.Now())
	x.BlockHistory.SetBlockCount(x.BlockHistory.GetBlockCount() + 1)
	x.mu.Unlock()
}

func (h *RejectHistory) Get() *gc.BlockHistoryList {
	var objects []*gc.BlockHistory
	dumpProcess := false
	for _, v := range h.store.Range {
		objects = append(objects, v.BlockHistory)
		if !dumpProcess && v.GetProcess() != "" {
			dumpProcess = true
		}
	}
	return gc.BlockHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: proto.Bool(dumpProcess),
	}.Build()
}
