package statistics

import (
	"context"
	"errors"
	"hash/maphash"
	"net"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type failedHistoryEntry struct {
	Protocol statistic.Type
	Host     string

	FailedCount atomic.Uint64
	Time        *atomicx.Value[time.Time]
	Error       *atomicx.Value[string]
	Process     *atomicx.Value[string]
}

type FailedHistory struct {
	store *lru.SyncLru[uint64, *failedHistoryEntry]
	seed  maphash.Seed
}

func NewFailedHistory() *FailedHistory {
	return &FailedHistory{
		store: lru.NewSyncLru(
			lru.WithCapacity[uint64, *failedHistoryEntry](int(configuration.HistorySize)),
		),
		seed: maphash.MakeSeed(),
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

	realAddr := getRealAddr(store, host)

	key := maphash.Comparable(h.seed, struct {
		host     string
		process  string
		protocol statistic.Type
	}{
		host:     realAddr,
		process:  store.GetProcessName(),
		protocol: protocol,
	})

	x, ok := h.store.LoadOrAdd(key, func() *failedHistoryEntry {
		fe := &failedHistoryEntry{
			Protocol:    protocol,
			Host:        realAddr,
			Error:       atomicx.NewValue(err.Error()),
			Time:        atomicx.NewValue(time.Now()),
			Process:     atomicx.NewValue(store.GetProcessName()),
			FailedCount: atomic.Uint64{},
		}
		fe.FailedCount.Add(1)
		return fe
	})
	if !ok {
		return
	}

	x.Time.Store(time.Now())
	x.FailedCount.Add(1)
	x.Error.Store(err.Error())
	x.Process.Store(store.GetProcessName())
}

func (h *FailedHistory) Get() *api.FailedHistoryList {
	var objects []*api.FailedHistory
	dumpProcess := false
	for _, v := range h.store.Range {
		afh := &api.FailedHistory{}
		afh.SetHost(v.Host)
		afh.SetProtocol(v.Protocol)
		afh.SetError(v.Error.Load())
		afh.SetTime(timestamppb.New(v.Time.Load()))
		afh.SetFailedCount(v.FailedCount.Load())
		afh.SetProcess(v.Process.Load())
		objects = append(objects, afh)
		if !dumpProcess && v.Process.Load() != "" {
			dumpProcess = true
		}
	}

	return api.FailedHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: proto.Bool(dumpProcess),
	}.Build()
}

type History struct {
	infoStore InfoCache
	store     *lru.SyncLru[uint64, *historyEntry]
	seed      maphash.Seed
}

type historyEntry struct {
	time  *atomicx.Value[time.Time]
	id    atomic.Uint64
	count atomic.Uint64
}

func NewHistory(infoStore InfoCache) *History {
	h := &History{
		infoStore: infoStore,
		seed:      maphash.MakeSeed(),
	}

	h.store = lru.NewSyncLru(
		lru.WithCapacity[uint64, *historyEntry](int(configuration.HistorySize)),
		lru.WithOnRemove(func(key uint64, value *historyEntry) {
			h.infoStore.Delete(value.id.Load())
		}),
	)

	return h
}

func (h *History) Push(c *statistic.Connection) {
	key := maphash.Comparable(h.seed, struct {
		addr     string
		process  string
		protocol statistic.Type
	}{
		addr:     c.GetAddr(),
		process:  c.GetProcess(),
		protocol: c.GetType().GetConnType(),
	})

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

func (h *History) Get() *api.AllHistoryList {
	dumpProcess := false
	var objects []*api.AllHistory
	for _, v := range h.store.Range {
		info, ok := h.infoStore.Load(v.id.Load())
		if !ok {
			continue
		}

		objects = append(objects, api.AllHistory_builder{
			Count:      proto.Uint64(v.count.Load()),
			Time:       timestamppb.New(v.time.Load()),
			Connection: info,
		}.Build())

		if !dumpProcess && info.GetProcess() != "" {
			dumpProcess = true
		}
	}

	return api.AllHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: proto.Bool(dumpProcess),
	}.Build()
}

func (h *History) Close() error {
	return h.infoStore.Close()
}
