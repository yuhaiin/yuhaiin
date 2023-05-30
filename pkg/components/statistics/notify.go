package statistics

import (
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type notify struct {
	notifierIDSeed id.IDGenerator
	notifier       syncmap.SyncMap[uint64, gs.Connections_NotifyServer]
}

func (n *notify) register(s gs.Connections_NotifyServer, conns ...connection) uint64 {
	id := n.notifierIDSeed.Generate()
	n.notifier.Store(id, s)
	s.Send(&gs.NotifyData{
		Data: &gs.NotifyData_NotifyNewConnections{
			NotifyNewConnections: &gs.NotifyNewConnections{
				Connections: slice.To(conns, func(c connection) *statistic.Connection { return c.Info() }),
			},
		},
	})
	return id
}

func (n *notify) unregister(id uint64) { n.notifier.Delete(id) }

func (n *notify) pubNewConns(conns ...connection) {
	if len(conns) == 0 {
		return
	}

	var cons []*statistic.Connection
	n.notifier.Range(func(key uint64, value gs.Connections_NotifyServer) bool {
		if cons == nil {
			cons = slice.To(conns, func(c connection) *statistic.Connection { return c.Info() })
		}

		value.Send(&gs.NotifyData{
			Data: &gs.NotifyData_NotifyNewConnections{
				NotifyNewConnections: &gs.NotifyNewConnections{
					Connections: cons,
				},
			},
		})

		return true
	})
}

func (n *notify) pubRemoveConns(ids ...uint64) {
	n.notifier.Range(func(key uint64, value gs.Connections_NotifyServer) bool {
		value.Send(&gs.NotifyData{
			Data: &gs.NotifyData_NotifyRemoveConnections{
				NotifyRemoveConnections: &gs.NotifyRemoveConnections{
					Ids: ids,
				},
			},
		})

		return true
	})
}
