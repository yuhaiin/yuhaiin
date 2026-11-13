package node

import (
	"context"
	"net/netip"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

type lanLinkRoute struct {
	nodeID   string
	prefixes []netip.Prefix
}

func prepareLANLinkRoutes(nodes []contractnode.Node) []lanLinkRoute {
	var routes []lanLinkRoute
	for _, node := range nodes {
		if !node.Enabled || len(node.Chain) != 1 || node.Chain[0].LANLink == nil {
			continue
		}
		invitation, err := transport.ParseLANLinkInvitation(node.Chain[0].LANLink.Invitation)
		if err != nil {
			continue
		}
		prefixes, err := invitation.Prefixes()
		if err == nil {
			routes = append(routes, lanLinkRoute{nodeID: node.ID, prefixes: prefixes})
		}
	}
	return routes
}

func (r *NodeRuntime) LANLinkTarget(ctx context.Context, addr netip.Addr) (route.Target, bool) {
	routes := r.lanLinkRoutes.Load()
	if routes == nil {
		if _, err := r.openNodes(ctx); err != nil {
			return route.Target{}, false
		}
		routes = r.lanLinkRoutes.Load()
		if routes == nil {
			return route.Target{}, false
		}
	}
	addr = addr.Unmap()
	longest, selected, ambiguous := -1, "", false
	for _, candidate := range *routes {
		prefixes := candidate.prefixes
		if entry, ok := r.proxies.store.Load(candidate.nodeID); ok {
			entry.mu.RLock()
			if live, ok := entry.Proxy.(interface{ LANLinkRoutes() ([]netip.Prefix, bool) }); ok {
				if assigned, ok := live.LANLinkRoutes(); ok {
					prefixes = assigned
				}
			}
			entry.mu.RUnlock()
		}
		for _, prefix := range prefixes {
			if !prefix.Contains(addr) {
				continue
			}
			if bits := prefix.Bits(); bits > longest {
				longest, selected, ambiguous = bits, candidate.nodeID, false
			} else if bits == longest && candidate.nodeID != selected {
				ambiguous = true
			}
		}
	}
	if longest < 0 || ambiguous {
		return route.Target{}, ambiguous
	}
	return route.Target{Type: "node", ID: selected}, true
}
