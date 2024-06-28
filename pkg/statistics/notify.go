package statistics

import (
	"context"
	"fmt"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type notifierEntry struct {
	s      gs.Connections_NotifyServer
	cancel context.CancelCauseFunc
}

type notify struct {
	closed context.Context

	channel  chan *gs.NotifyData
	close    context.CancelFunc
	notifier syncmap.SyncMap[uint64, *notifierEntry]

	notifierIDSeed id.IDGenerator
	mu             sync.RWMutex
}

func newNotify() *notify {
	ctx, cancel := context.WithCancel(context.Background())
	n := &notify{
		channel: make(chan *gs.NotifyData, 1000),
		closed:  ctx,
		close:   cancel,
	}

	go n.start()

	return n
}

func (n *notify) register(s gs.Connections_NotifyServer, conns ...connection) (uint64, context.Context) {
	id := n.notifierIDSeed.Generate()
	ctx, cancel := context.WithCancelCause(context.Background())

	err := s.Send(&gs.NotifyData{
		Data: &gs.NotifyData_NotifyNewConnections{
			NotifyNewConnections: &gs.NotifyNewConnections{
				Connections: slice.To(conns, func(c connection) *statistic.Connection { return c.Info() }),
			},
		},
	})
	if err != nil {
		cancel(fmt.Errorf("send notify error: %w", err))
	} else {
		n.notifier.Store(id, &notifierEntry{
			s:      s,
			cancel: cancel,
		})
	}

	return id, ctx
}

func (n *notify) unregister(id uint64) { n.notifier.Delete(id) }

func (n *notify) start() {
	for {
		select {
		case <-n.closed.Done():
			close(n.channel)
			return
		case d := <-n.channel:
			n.notifier.Range(func(key uint64, value *notifierEntry) bool {
				if err := value.s.Send(d); err != nil {
					value.cancel(fmt.Errorf("send notify error: %w", err))
				}
				return true
			})
		}
	}
}

func (n *notify) pubNewConns(conns ...connection) {
	if len(conns) == 0 {
		return
	}

	n.mu.RLock()
	defer n.mu.RUnlock()

	select {
	case <-n.closed.Done():
		return
	default:
	}

	select {
	case <-n.closed.Done():
	case n.channel <- &gs.NotifyData{
		Data: &gs.NotifyData_NotifyNewConnections{
			NotifyNewConnections: &gs.NotifyNewConnections{
				Connections: slice.To(conns, func(c connection) *statistic.Connection { return c.Info() }),
			},
		},
	}:
	}
}

func (n *notify) pubRemoveConns(ids ...uint64) {
	if len(ids) == 0 {
		return
	}

	n.mu.RLock()
	defer n.mu.RUnlock()

	select {
	case <-n.closed.Done():
		return
	default:
	}

	n.channel <- &gs.NotifyData{
		Data: &gs.NotifyData_NotifyRemoveConnections{
			NotifyRemoveConnections: &gs.NotifyRemoveConnections{
				Ids: ids,
			},
		},
	}
}

func (n *notify) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.close()
	return nil
}
