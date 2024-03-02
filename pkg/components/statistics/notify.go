package statistics

import (
	"context"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type notify struct {
	mu sync.RWMutex

	notifierIDSeed id.IDGenerator
	notifier       syncmap.SyncMap[uint64, gs.Connections_NotifyServer]

	channel chan *gs.NotifyData
	closed  context.Context
	close   context.CancelFunc
}

func newNotify() *notify {
	ctx, cancel := context.WithCancel(context.Background())
	n := &notify{
		channel: make(chan *gs.NotifyData, 100),
		closed:  ctx,
		close:   cancel,
	}

	go n.start()

	return n
}

func (n *notify) register(s gs.Connections_NotifyServer, conns ...connection) uint64 {
	id := n.notifierIDSeed.Generate()
	n.notifier.Store(id, s)
	_ = s.Send(&gs.NotifyData{
		Data: &gs.NotifyData_NotifyNewConnections{
			NotifyNewConnections: &gs.NotifyNewConnections{
				Connections: slice.To(conns, func(c connection) *statistic.Connection { return c.Info() }),
			},
		},
	})
	return id
}

func (n *notify) unregister(id uint64) { n.notifier.Delete(id) }

func (n *notify) start() {
	for {
		select {
		case <-n.closed.Done():
			close(n.channel)
			return
		case d := <-n.channel:
			n.notifier.Range(func(key uint64, value gs.Connections_NotifyServer) bool {
				_ = value.Send(d)
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

	n.channel <- &gs.NotifyData{
		Data: &gs.NotifyData_NotifyNewConnections{
			NotifyNewConnections: &gs.NotifyNewConnections{
				Connections: slice.To(conns, func(c connection) *statistic.Connection { return c.Info() }),
			},
		},
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
