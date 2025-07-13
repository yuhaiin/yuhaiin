package statistics

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type notifierEntry struct {
	s      gs.Connections_NotifyServer
	cancel context.CancelCauseFunc
}

func (n *notifierEntry) Send(data *gs.NotifyData) error {
	err := n.s.Send(data)
	if err != nil {
		n.cancel(fmt.Errorf("send notify error: %w", err))
	}

	return err
}

func (n *notifierEntry) Context() context.Context {
	return n.s.Context()
}

type notify struct {
	notifyTrigger chan struct{}
	notifyStore   *notifyStore
	notifier      syncmap.SyncMap[uint64, *notifierEntry]

	notifierIDSeed id.IDGenerator
	closed         atomic.Bool
}

func newNotify() *notify {
	n := &notify{
		notifyTrigger: make(chan struct{}, 1),
		notifyStore:   newNotifyStore(),
	}

	go n.start()

	return n
}

func (n *notify) register(s gs.Connections_NotifyServer, conns []*statistic.Connection) (uint64, context.Context) {
	id := n.notifierIDSeed.Generate()
	ctx, cancel := context.WithCancelCause(context.Background())

	ne := &notifierEntry{
		s:      s,
		cancel: cancel,
	}

	err := ne.Send((&gs.NotifyData_builder{
		NotifyNewConnections: (&gs.NotifyNewConnections_builder{
			Connections: conns,
		}).Build(),
	}).Build())
	if err == nil {
		n.notifier.Store(id, ne)
	}

	return id, ctx
}

func (n *notify) unregister(id uint64) { n.notifier.Delete(id) }

func (n *notify) send() {
	datas := n.notifyStore.dump()

	for notifier := range n.notifier.RangeValues {
	_loopNotifyDatas:
		for _, data := range datas {
			select {
			case <-notifier.Context().Done():
				continue
			default:
			}

			err := notifier.Send(data)
			if err != nil {
				break _loopNotifyDatas
			}
		}
	}
}

func (n *notify) start() {
	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()

	for {
		select {
		case <-n.notifyTrigger:
			if n.closed.Load() {
				return
			}
			n.send()

		case <-ticker.C:
			if n.closed.Load() {
				return
			}
			n.send()
		}
	}
}

func (n *notify) trigger() {
	select {
	case n.notifyTrigger <- struct{}{}:
	default:
	}
}

func (n *notify) pubNewConn(conn *statistic.Connection) {
	if n.closed.Load() {
		return
	}

	if n.notifyStore.push(conn) > 13 {
		n.trigger()
	}
}

func (n *notify) pubRemoveConn(id uint64) {
	if n.closed.Load() {
		return
	}

	if n.notifyStore.remove(id) > 13 {
		n.trigger()
	}
}

func (n *notify) Close() error {
	n.closed.Store(true)
	return nil
}

type notifyStore struct {
	removeStore *set.Set[uint64]
	store       map[uint64]*statistic.Connection
	length      uint64
	mu          sync.RWMutex
}

func newNotifyStore() *notifyStore {
	return &notifyStore{
		store:       make(map[uint64]*statistic.Connection),
		removeStore: set.NewSet[uint64](),
	}
}

func (n *notifyStore) push(o *statistic.Connection) int {
	n.mu.Lock()
	n.store[o.GetId()] = o
	n.length++
	len := n.length
	n.mu.Unlock()

	return int(len)
}

func (n *notifyStore) remove(id uint64) int {
	n.mu.Lock()

	_, ok := n.store[id]
	if ok {
		delete(n.store, id)
		n.length--
	} else {
		n.length++
		n.removeStore.Push(id)
	}
	len := n.length

	n.mu.Unlock()

	return int(len)
}

func (n *notifyStore) dump() (datas []*gs.NotifyData) {
	n.mu.Lock()
	defer n.mu.Unlock()

	removeIDs := slices.Collect(n.removeStore.Range)
	n.removeStore.Clear()
	newConns := slices.Collect(maps.Values(n.store))
	clear(n.store)
	n.length = 0

	if len(removeIDs) > 0 {
		datas = append(datas, (&gs.NotifyData_builder{
			NotifyRemoveConnections: (&gs.NotifyRemoveConnections_builder{
				Ids: removeIDs,
			}).Build(),
		}).Build())
	}

	if len(newConns) > 0 {
		datas = append(datas, (&gs.NotifyData_builder{
			NotifyNewConnections: (&gs.NotifyNewConnections_builder{
				Connections: newConns,
			}).Build(),
		}).Build())
	}

	return
}
