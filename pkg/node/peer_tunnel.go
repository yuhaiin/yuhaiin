package node

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/net/peerrendezvous"
)

const peerPageSize = 16

// PeerTunnelPeers checks the configured pairings without starting or replacing
// any data-plane session. The caller receives only public peer metadata.
func (r *NodeRuntime) PeerTunnelPeers(ctx context.Context, page int) (contract.PeerTunnelPeers, error) {
	if _, err := r.openNodes(ctx); err != nil {
		return contract.PeerTunnelPeers{}, err
	}
	type pairing struct {
		id, name string
		config   *transport.PeerTunnel
	}
	var pairings []pairing
	for _, n := range r.selectors.snapshot.Load().nodes {
		if !n.Enabled {
			continue
		}
		for _, step := range n.Chain {
			if step.PeerTunnel != nil {
				pairings = append(pairings, pairing{n.ID, n.Name, step.PeerTunnel})
				break
			}
		}
	}
	slices.SortFunc(pairings, func(a, b pairing) int {
		return cmp.Or(cmp.Compare(a.name, b.name), cmp.Compare(a.id, b.id))
	})
	total := len(pairings)
	page = min(max(page, 1), max(1, (total+peerPageSize-1)/peerPageSize))
	pairings = pairings[(page-1)*peerPageSize : min(page*peerPageSize, total)]
	items := make([]contract.PeerTunnelPeer, len(pairings))
	var wg sync.WaitGroup
	for i, pairing := range pairings {
		wg.Go(func() {
			peer := lookupTunnelPeer(ctx, pairing.config)
			peer.NodeID, peer.Name = pairing.id, pairing.name
			items[i] = peer
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return contract.PeerTunnelPeers{}, err
	}
	return contract.PeerTunnelPeers{Items: items, Page: route.Page{Page: page, PageSize: peerPageSize, Total: total}}, nil
}

func lookupTunnelPeer(ctx context.Context, c *transport.PeerTunnel) contract.PeerTunnelPeer {
	result := contract.PeerTunnelPeer{State: "unknown", TunnelIP: c.PeerIP, Routes: slices.Clone(c.Routes)}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	token, err := transport.DecodePeerKey(c.Token)
	if err != nil {
		return result
	}
	coordinator, err := peerrendezvous.ResolveCoordinator(ctx, c.Coordinator)
	if err != nil {
		return result
	}
	registration, err := peerrendezvous.Lookup(ctx, coordinator, token)
	if err != nil {
		return result
	}
	endpoint := registration.Endpoint
	switch {
	case registration.Denial != "":
		result.State = registration.Denial
	case !endpoint.IsValid() || endpoint == coordinator:
		result.State = "offline"
	case endpoint.Addr().BitLen() != coordinator.Addr().BitLen():
		result.State, result.Endpoint = "incompatible", endpoint.String()
	default:
		result.State, result.Endpoint = "online", endpoint.String()
	}
	return result
}
