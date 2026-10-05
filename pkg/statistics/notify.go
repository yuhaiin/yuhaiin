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
	events chan contractconnection.Event
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
	done          chan struct{}
	notifyStore   *notifyStore
	notifier      syncmap.SyncMap[uint64, *notifierEntry]

	notifierIDSeed id.IDGenerator
	closed         atomic.Bool
	subscribers    atomic.Int64
}

func newNotify() *notify {
	n := &notify{
		notifyTrigger: make(chan struct{}, 1),
		done:          make(chan struct{}),
		notifyStore:   newNotifyStore(),
	}

	go n.start()

	return n
}

func (n *notify) register(s control.ServerStream[contractconnection.Event]) (uint64, context.Context) {
	id := n.notifierIDSeed.Generate()
	ctx, cancel := context.WithCancelCause(context.Background())
	if n.closed.Load() {
		cancel(context.Canceled)
		return id, ctx
	}

	ne := &notifierEntry{
		s:      s,
		cancel: cancel,
		events: make(chan contractconnection.Event, 16),
	}
	n.subscribers.Add(1)
	n.notifier.Store(id, ne)
	// Close may race with registration after its Range has already passed.
	// Re-check after publishing so either side is guaranteed to cancel us.
	if n.closed.Load() {
		n.unregister(id)
		cancel(context.Canceled)
	}

	return id, ctx
}

func (n *notify) unregister(id uint64) {
	if _, ok := n.notifier.LoadAndDelete(id); ok {
		n.subscribers.Add(-1)
	}
}

func (n *notify) send() {
	datas := n.notifyStore.dump()

	for notifier := range n.notifier.RangeValues {
		for _, data := range datas {
			select {
			case <-notifier.Context().Done():
				notifier.cancel(context.Canceled)
			case notifier.events <- data:
			default:
				// A slow subscriber must reconnect for a fresh snapshot, rather
				// than stall delivery and shutdown for every other subscriber.
				notifier.cancel(fmt.Errorf("connection event subscriber is too slow"))
			}
		}
	}
}

func (n *notify) start() {
	defer close(n.done)
	const debounce = 250 * time.Millisecond

	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-n.notifyTrigger:
			if n.closed.Load() {
				return
			}
			if timerC == nil {
				if timer == nil {
					timer = time.NewTimer(debounce)
				} else {
					timer.Reset(debounce)
				}
				timerC = timer.C
			}
		case <-timerC:
			if n.closed.Load() {
				return
			}
			n.send()
			timerC = nil
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
	if n.closed.Load() || n.subscribers.Load() == 0 {
		return
	}

	n.notifyStore.push(conn)
	n.trigger()
}

func (n *notify) pubRemoveConn(id uint64) {
	if n.closed.Load() || n.subscribers.Load() == 0 {
		return
	}

	n.notifyStore.remove(id)
	n.trigger()
}

func (n *notify) Close() error {
	if n.closed.CompareAndSwap(false, true) {
		n.trigger()
	}
	for entry := range n.notifier.RangeValues {
		entry.cancel(context.Canceled)
	}
	<-n.done
	return nil
}

type notifyStore struct {
	removeStore *set.Set[uint64]
	store       map[uint64]contractconnection.Connection
	mu          sync.RWMutex
}

func newNotifyStore() *notifyStore {
	return &notifyStore{
		store:       make(map[uint64]contractconnection.Connection),
		removeStore: set.NewSet[uint64](),
	}
}

func (n *notifyStore) push(o contractconnection.Connection) {
	n.mu.Lock()
	id, _ := strconv.ParseUint(o.ID, 10, 64)
	n.store[id] = o
	n.mu.Unlock()
}

func (n *notifyStore) remove(id uint64) {
	n.mu.Lock()
	delete(n.store, id)
	// An initial subscriber snapshot may already contain a pending addition.
	// Always publish removal, even if the addition has not been broadcast yet.
	n.removeStore.Push(id)
	n.mu.Unlock()
}

func (n *notifyStore) dump() (datas []contractconnection.Event) {
	n.mu.Lock()
	defer n.mu.Unlock()

	removeIDs := slices.Collect(n.removeStore.Range)
	n.removeStore.Clear()
	newConns := slices.Collect(maps.Values(n.store))
	clear(n.store)

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
