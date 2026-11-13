package node

import (
	"cmp"
	"context"
	"net/netip"
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
		config   peerPairing
	}
	var pairings []pairing
	for _, n := range r.selectors.snapshot.Load().nodes {
		if !n.Enabled {
			continue
		}
		for _, step := range n.Chain {
			if step.LANLink != nil {
				if invitation, err := transport.ParseLANLinkInvitation(step.LANLink.Invitation); err == nil {
					pairings = append(pairings, pairing{n.ID, n.Name, peerPairing{
						Coordinator: invitation.Coordinator, Token: invitation.Registration, Routes: invitation.Routes,
					}})
				}
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
			peer.Link = r.lanLinkStatus(pairing.id, pairing.config)
			if peer.Link.PeerIP != "" {
				peer.TunnelIP = peer.Link.PeerIP
			}
			items[i] = peer
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return contract.PeerTunnelPeers{}, err
	}
	return contract.PeerTunnelPeers{Items: items, Page: route.Page{Page: page, PageSize: peerPageSize, Total: total}}, nil
}

// lanLinkStatus reads the running outbound, or describes an idle one from its
// invitation when the node has not been used yet.
func (r *NodeRuntime) lanLinkStatus(nodeID string, c peerPairing) *transport.LANLinkStatus {
	if entry, ok := r.proxies.store.Load(nodeID); ok {
		entry.mu.RLock()
		live, ok := entry.Proxy.(interface {
			LANLinkStatus() transport.LANLinkStatus
		})
		entry.mu.RUnlock()
		if ok {
			return new(live.LANLinkStatus())
		}
	}
	status := &transport.LANLinkStatus{State: "idle", Coordinator: c.Coordinator}
	if key, err := transport.DecodePeerKey(c.Token); err == nil {
		status.PairingID = transport.PeerPairIDString(key)
	}
	return status
}

// peerPairing is what the coordinator lookup needs from an invitation.
type peerPairing struct {
	Coordinator string
	Token       string
	Routes      []string
}

func lookupTunnelPeer(ctx context.Context, c peerPairing) contract.PeerTunnelPeer {
	result := contract.PeerTunnelPeer{State: "unknown", Routes: slices.Clone(c.Routes)}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	token, err := transport.DecodePeerKey(c.Token)
	if err != nil {
		return result
	}
	coordinators, err := peerrendezvous.ResolveCoordinators(ctx, c.Coordinator)
	if err != nil {
		return result
	}
	registration, err := peerrendezvous.LookupAny(ctx, coordinators, token)
	if err != nil {
		return result
	}
	endpoint := registration.Endpoint
	switch {
	case registration.Denial != "":
		result.State = registration.Denial
	case !endpoint.IsValid() || slices.Contains(coordinators, endpoint):
		result.State = "offline"
	case !slices.ContainsFunc(coordinators, func(c netip.AddrPort) bool { return c.Addr().BitLen() == endpoint.Addr().BitLen() }):
		// The tunnel can follow the publisher only to a family the
		// discovery server is reachable on.
		result.State, result.Endpoint = "incompatible", endpoint.String()
	default:
		result.State, result.Endpoint = "online", endpoint.String()
	}
	return result
}
