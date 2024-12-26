package statistics

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type failedHistoryKey struct {
	protocol string
	host     string
	process  string
}

type failedHistoryEntry struct {
	*gs.FailedHistory
	mu sync.Mutex
}

type FailedHistory struct {
	store       *lru.SyncLru[failedHistoryKey, *failedHistoryEntry]
	dumpProcess bool
}

func NewFailedHistory() *FailedHistory {
	return &FailedHistory{
		store: lru.NewSyncLru(
			lru.WithCapacity[failedHistoryKey, *failedHistoryEntry](1000),
		),
	}
}

func (h *FailedHistory) Push(ctx context.Context, err error, protocol string, host netapi.Address) {
	if err == nil || netapi.IsBlockError(err) {
		return
	}

	store := netapi.GetContext(ctx)

	if !h.dumpProcess && store.Process != "" {
		h.dumpProcess = true
	}

	de := &netapi.DialError{}
	if errors.As(err, &de) && de.Err != nil {
		err = de.Err
	}

	ne := &net.OpError{}
	if errors.As(err, &ne) {
		err = ne.Err
	}

	key := failedHistoryKey{protocol, getRealAddr(store, host), store.Process}
	x, ok := h.store.LoadOrAdd(key, func() *failedHistoryEntry {
		return &failedHistoryEntry{
			FailedHistory: &gs.FailedHistory{
				Protocol:    protocol,
				Host:        getRealAddr(store, host),
				Error:       err.Error(),
				Time:        timestamppb.Now(),
				Process:     store.Process,
				FailedCount: 1,
			},
		}
	})

	if !ok {
		return
	}

	x.mu.Lock()
	x.Time = timestamppb.Now()
	x.FailedCount++
	x.Error = err.Error()
	x.mu.Unlock()
}

func (h *FailedHistory) Get() *gs.FailedHistoryList {
	var objects []*gs.FailedHistory
	for _, v := range h.store.Range {
		objects = append(objects, v.FailedHistory)
	}
	return &gs.FailedHistoryList{
		Objects:            objects,
		DumpProcessEnabled: h.dumpProcess,
	}
}

type History struct {
	store       *lru.SyncLru[failedHistoryKey, *historyEntry]
	dumpProcess atomic.Bool
}

type historyEntry struct {
	*gs.AllHistory
	mu sync.Mutex
}

func NewHistory() *History {
	return &History{
		store: lru.NewSyncLru(
			lru.WithCapacity[failedHistoryKey, *historyEntry](1000),
		),
	}
}

func (h *History) Push(c *statistic.Connection) {
	key := failedHistoryKey{c.Type.ConnType.String(), c.Addr, c.Extra["Process"]}

	if !h.dumpProcess.Load() && key.process != "" {
		h.dumpProcess.Store(true)
	}

	x, ok := h.store.LoadOrAdd(key, func() *historyEntry {
		return &historyEntry{
			AllHistory: &gs.AllHistory{
				Connection: c,
				Count:      1,
				Time:       timestamppb.Now(),
			},
		}
	})

	if !ok {
		return
	}

	x.mu.Lock()
	x.Count++
	x.Time = timestamppb.Now()
	x.Connection = c
	x.mu.Unlock()
}

func (h *History) Get() *gs.AllHistoryList {
	var objects []*gs.AllHistory
	for _, v := range h.store.Range {
		objects = append(objects, v.AllHistory)
	}
	return &gs.AllHistoryList{
		Objects:            objects,
		DumpProcessEnabled: h.dumpProcess.Load(),
	}
}
