package statistics

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
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
	mu sync.RWMutex
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
				Host:        stringOrNil(getRealAddr(store, host)),
				Error:       stringOrNil(err.Error()),
				Time:        timestamppb.Now(),
				Process:     stringOrNil(store.GetProcessName()),
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
		v.mu.RLock()
		objects = append(objects, proto.CloneOf(v.FailedHistory))
		if !dumpProcess && v.FailedHistory.GetProcess() != "" {
			dumpProcess = true
		}
		v.mu.RUnlock()
	}

	return gs.FailedHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: proto.Bool(dumpProcess),
	}.Build()
}

type History struct {
	infoStore InfoCache
	store     *lru.SyncLru[failedHistoryKey, *historyEntry]
}

type historyEntry struct {
	id    atomic.Uint64
	count atomic.Uint64
	time  *atomicx.Value[time.Time]
}

func NewHistory(infoStore InfoCache) *History {
	h := &History{
		infoStore: infoStore,
	}

	h.store = lru.NewSyncLru(
		lru.WithCapacity[failedHistoryKey, *historyEntry](configuration.HistorySize),
		lru.WithOnRemove(func(key failedHistoryKey, value *historyEntry) {
			h.infoStore.Delete(value.id.Load())
		}),
	)

	return h
}

func (h *History) Push(c *statistic.Connection) {
	key := failedHistoryKey{c.GetAddr(), c.GetProcess(), c.GetType().GetConnType()}

	h.infoStore.Store(c.GetId(), c)

	x, ok := h.store.LoadOrAdd(key, func() *historyEntry {
		h := &historyEntry{time: atomicx.NewValue(time.Now())}
		h.id.Store(c.GetId())
		h.count.Store(1)

		return h
	})

	if !ok {
		return
	}

	x.count.Add(1)
	x.time.Store(time.Now())
	if oldId := x.id.Load(); x.id.CompareAndSwap(oldId, c.GetId()) {
		h.infoStore.Delete(oldId)
	}
}

func (h *History) Get() *gs.AllHistoryList {
	dumpProcess := false
	var objects []*gs.AllHistory
	for _, v := range h.store.Range {
		info, ok := h.infoStore.Load(v.id.Load())
		if !ok {
			continue
		}

		objects = append(objects, gs.AllHistory_builder{
			Count:      proto.Uint64(v.count.Load()),
			Time:       timestamppb.New(v.time.Load()),
			Connection: info,
		}.Build())

		if !dumpProcess && info.GetProcess() != "" {
			dumpProcess = true
		}
	}

	return gs.AllHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: proto.Bool(dumpProcess),
	}.Build()
}

func (h *History) Close() error {
	return h.infoStore.Close()
}
