package statistics

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/control"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type notifierEntry struct {
	s      control.ServerStream[contractconnection.Event]
	cancel context.CancelCauseFunc
}

func (n *notifierEntry) Send(data contractconnection.Event) error {
	err := n.s.Send(&data)
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

func (n *notify) register(s control.ServerStream[contractconnection.Event], conns []contractconnection.Connection) (uint64, context.Context) {
	id := n.notifierIDSeed.Generate()
	ctx, cancel := context.WithCancelCause(context.Background())

	ne := &notifierEntry{
		s:      s,
		cancel: cancel,
	}

	err := ne.Send(contractconnection.Event{
		Type:    "connections_added",
		Payload: contractconnection.Connections{Connections: conns},
	})
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

func (n *notify) pubNewConn(conn contractconnection.Connection) {
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
	store       map[uint64]contractconnection.Connection
	length      uint64
	mu          sync.RWMutex
}

func newNotifyStore() *notifyStore {
	return &notifyStore{
		store:       make(map[uint64]contractconnection.Connection),
		removeStore: set.NewSet[uint64](),
	}
}

func (n *notifyStore) push(o contractconnection.Connection) int {
	n.mu.Lock()
	id, _ := strconv.ParseUint(o.ID, 10, 64)
	n.store[id] = o
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

func (n *notifyStore) dump() (datas []contractconnection.Event) {
	n.mu.Lock()
	defer n.mu.Unlock()

	removeIDs := slices.Collect(n.removeStore.Range)
	n.removeStore.Clear()
	newConns := slices.Collect(maps.Values(n.store))
	clear(n.store)
	n.length = 0

	if len(removeIDs) > 0 {
		ids := make([]string, 0, len(removeIDs))
		for _, id := range removeIDs {
			ids = append(ids, formatUint64(id))
		}
		datas = append(datas, contractconnection.Event{
			Type:    "connections_removed",
			Payload: contractconnection.CloseRequest{IDs: ids},
		})
	}

	if len(newConns) > 0 {
		datas = append(datas, contractconnection.Event{
			Type:    "connections_added",
			Payload: contractconnection.Connections{Connections: newConns},
		})
	}

	return
}
