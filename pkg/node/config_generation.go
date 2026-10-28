package node

import (
	"context"
	"errors"
	"reflect"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

var errNodeReconfigured = errors.New("outbound configuration changed before connection creation")

func (o *nodeObserver) generations() map[string]uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make(map[string]uint64, len(o.nodes))
	for id, c := range o.nodes {
		out[id] = c.generation.Load()
	}
	return out
}
func (o *nodeObserver) invalidateHealth(id string) {
	n := o.counter(id)
	n.mu.Lock()
	defer n.mu.Unlock()
	// Unique across deletions/recreations as well as transport revisions; a
	// stale plan cannot pass validation when an administrator reuses a Node ID.
	n.generation.Store(o.nextGeneration.Add(1))
	n.circuitListeners.Store(nil)
	n.selectionHealth = nil
	n.tcpHealth, n.udpHealth = contract.ChannelHealth{}, contract.ChannelHealth{}
	n.throughput, n.uploadThroughput = contract.ThroughputMeasurement{}, contract.ThroughputMeasurement{}
}
func (r *NodeRuntime) cachedNode(ctx context.Context, id string) (contract.Node, uint64, error) {
	if _, err := r.openNodes(ctx); err != nil {
		return contract.Node{}, 0, err
	}
	snapshot := r.selectors.snapshot.Load()
	if snapshot == nil {
		return contract.Node{}, 0, plainstore.ErrNotFound
	}
	n, ok := snapshot.nodes[id]
	if !ok {
		return n, 0, plainstore.ErrNotFound
	}
	return n, snapshot.generations[id], nil
}
func sameNodeTransport(a, b contract.Node) bool {
	return a.Enabled == b.Enabled && a.IPVersion == b.IPVersion && reflect.DeepEqual(a.Chain, b.Chain)
}
