package statistics

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type failedHistoryKey struct {
	host     string
	process  string
	protocol statistic.Type
}

type failedHistoryEntry struct {
	*gs.FailedHistory
	mu sync.Mutex
}

type FailedHistory struct {
	store *lru.SyncLru[failedHistoryKey, *failedHistoryEntry]
}

func NewFailedHistory() *FailedHistory {
	return &FailedHistory{
		store: lru.NewSyncLru(
			lru.WithCapacity[failedHistoryKey, *failedHistoryEntry](configuration.HistorySize),
		),
	}
}

func (h *FailedHistory) Push(ctx context.Context, err error, protocol statistic.Type, host netapi.Address) {
	if err == nil || netapi.IsBlockError(err) {
		return
	}

	store := netapi.GetContext(ctx)

	de := &netapi.DialError{}
	if errors.As(err, &de) && de.Err != nil {
		err = de.Err
	}

	ne := &net.OpError{}
	if errors.As(err, &ne) {
		err = ne.Err
	}

	key := failedHistoryKey{getRealAddr(store, host), store.GetProcessName(), protocol}
	x, ok := h.store.LoadOrAdd(key, func() *failedHistoryEntry {
		return &failedHistoryEntry{
			FailedHistory: (&gs.FailedHistory_builder{
				Protocol:    &protocol,
				Host:        proto.String(getRealAddr(store, host)),
				Error:       proto.String(err.Error()),
				Time:        timestamppb.Now(),
				Process:     proto.String(store.GetProcessName()),
				FailedCount: proto.Uint64(1),
			}).Build(),
		}
	})

	if !ok {
		return
	}

	x.mu.Lock()
	x.SetTime(timestamppb.Now())
	x.SetFailedCount(x.GetFailedCount() + 1)
	x.SetError(err.Error())
	x.mu.Unlock()
}

func (h *FailedHistory) Get() *gs.FailedHistoryList {
	var objects []*gs.FailedHistory
	dumpProcess := false
	for _, v := range h.store.Range {
		objects = append(objects, v.FailedHistory)
		if !dumpProcess && v.FailedHistory.GetProcess() != "" {
			dumpProcess = true
		}
	}

	return proto.Clone(gs.FailedHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: proto.Bool(dumpProcess),
	}.Build()).(*gs.FailedHistoryList)
}

type History struct {
	store *lru.SyncLru[failedHistoryKey, *historyEntry]
}

type historyEntry struct {
	*gs.AllHistory
	mu sync.Mutex
}

func NewHistory() *History {
	return &History{
		store: lru.NewSyncLru(
			lru.WithCapacity[failedHistoryKey, *historyEntry](configuration.HistorySize),
		),
	}
}

func (h *History) Push(c *statistic.Connection) {
	key := failedHistoryKey{c.GetAddr(), c.GetProcess(), c.GetType().GetConnType()}

	x, ok := h.store.LoadOrAdd(key, func() *historyEntry {
		return &historyEntry{
			AllHistory: (&gs.AllHistory_builder{
				Connection: c,
				Count:      proto.Uint64(1),
				Time:       timestamppb.Now(),
			}).Build(),
		}
	})

	if !ok {
		return
	}

	x.mu.Lock()
	x.SetCount(x.GetCount() + 1)
	x.SetTime(timestamppb.Now())
	x.SetConnection(c)
	x.mu.Unlock()
}

func (h *History) Get() *gs.AllHistoryList {
	dumpProcess := false
	var objects []*gs.AllHistory
	for _, v := range h.store.Range {
		objects = append(objects, v.AllHistory)
		if !dumpProcess && v.GetConnection().GetProcess() != "" {
			dumpProcess = true
		}
	}

	return proto.Clone(gs.AllHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: proto.Bool(dumpProcess),
	}.Build()).(*gs.AllHistoryList)
}
