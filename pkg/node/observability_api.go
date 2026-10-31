package node

import (
	"context"
	"errors"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

// Statuses reads only caller-selected node IDs; paging stays at the directory
// API. Observing a status never constructs a Proxy or initiates a probe.
func (r *NodeRuntime) Statuses(ctx context.Context, ids []string) ([]contract.RuntimeStatus, error) {
	if len(ids) > 100 {
		return nil, errors.New("too many outbound node status IDs")
	}
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]contract.RuntimeStatus, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		node, err := nodes.Get(ctx, id)
		if errors.Is(err, plainstore.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		s := r.observer.status(id)
		if !node.Enabled {
			s.State = "disabled"
		}
		// A native provider is optional; it supplements rather than replaces
		// generic passive observations, and cannot wake an unused VPN client.
		if entry, ok := r.proxies.store.Load(id); ok && entry.mu.TryRLock() {
			if provider, ok := entry.Proxy.(contract.NodeRuntimeStatusProvider); ok {
				native := provider.NodeRuntimeStatus()
				s.Protocol = &native
			}
			entry.mu.RUnlock()
		}
		out = append(out, s)
	}
	return out, nil
}
