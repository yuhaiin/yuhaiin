package node

import (
	"context"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
	autoConnectTimeout    = 3 * time.Minute
	autoConnectRetryFirst = 15 * time.Second
	autoConnectRetryMax   = 5 * time.Minute
)

// autoConnects reports whether a node connects without waiting for traffic. A
// LAN Link outbound that allows incoming flows must be up to receive them.
func autoConnects(n contract.Node) bool {
	if !n.Enabled {
		return false
	}
	if n.AutoConnect {
		return true
	}
	return len(n.Chain) == 1 && n.Chain[0].LANLink != nil && n.Chain[0].LANLink.AllowIncoming
}

// StartAutoConnect loads the nodes, which connects every auto-connect node.
// The service calls it once it is ready to carry traffic.
func (r *NodeRuntime) StartAutoConnect() {
	go func() {
		if _, err := r.openNodes(context.Background()); err != nil {
			log.Warn("auto-connect outbounds", "err", err)
		}
	}()
}

// startAutoConnect connects the auto-connect nodes that are not connecting
// yet. It runs on every node reload; a node whose transport changed gets a
// new generation and connects again.
func (r *NodeRuntime) startAutoConnect(nodes []contract.Node, generations map[string]uint64, stop <-chan struct{}) {
	for _, n := range nodes {
		if !autoConnects(n) {
			continue
		}
		generation := generations[n.ID]
		if previous, running := r.autoConnecting.Swap(n.ID, generation); running && previous == generation {
			continue
		}
		go func() {
			defer r.autoConnecting.CompareAndDelete(n.ID, generation)
			r.autoConnect(n.ID, generation, stop)
		}()
	}
}

// autoConnect opens the node and starts its session, retrying with backoff
// while the node stays an auto-connect node.
func (r *NodeRuntime) autoConnect(id string, generation uint64, stop <-chan struct{}) {
	delay := autoConnectRetryFirst
	for {
		err := r.connectNode(id)
		if err == nil {
			return
		}
		log.Warn("auto-connect outbound", "node", id, "err", err, "retry", delay)
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, autoConnectRetryMax)
		snapshot := r.selectors.snapshot.Load()
		if snapshot == nil {
			return
		}
		if n, ok := snapshot.nodes[id]; !ok || !autoConnects(n) || snapshot.generations[id] != generation {
			return
		}
	}
}

func (r *NodeRuntime) connectNode(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), autoConnectTimeout)
	defer cancel()
	if _, err := r.GetDialerByID(ctx, id); err != nil {
		return err
	}
	entry, ok := r.proxies.store.Load(id)
	if !ok || entry == nil {
		return nil
	}
	entry.mu.RLock()
	proxy := entry.Proxy
	entry.mu.RUnlock()
	if connector, ok := proxy.(netapi.AutoConnector); ok {
		return connector.AutoConnect(ctx)
	}
	return nil
}
