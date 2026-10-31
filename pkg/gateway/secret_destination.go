package gateway

import (
	"context"
	"reflect"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

// upstreamDestination is everything that decides who receives a forwarded request.
type upstreamDestination struct {
	Backends   []contract.Backend
	Outbound   route.Target
	ServerName string
	TrustPEM   string
}

func destinationOf(u contract.Upstream) upstreamDestination {
	return upstreamDestination{u.Backends, u.Outbound, u.ServerName, u.TrustPEM}
}

// authorizeUpstreamDestinations covers the reference an action's own fields cannot
// see: rewrite credentials are sent to whatever its named upstream resolves to.
// next must already have its markers resolved by secret.Merge.
func authorizeUpstreamDestinations(ctx context.Context, previous, next contract.Config) error {
	before := make(map[string]upstreamDestination, len(previous.Upstreams))
	for _, u := range previous.Upstreams {
		before[u.ID] = destinationOf(u)
	}
	changed := make(map[string]bool, len(next.Upstreams))
	for _, u := range next.Upstreams {
		if old, ok := before[u.ID]; ok && !reflect.DeepEqual(old, destinationOf(u)) {
			changed[u.ID] = true
		}
	}
	if len(changed) == 0 {
		return nil
	}
	exposes := func(a contract.Action) bool { return changed[a.Upstream] && secret.Holds(a.Rewrite) }
	for _, r := range next.Rules {
		if exposes(r.Action) {
			return secret.AuthorizeChange(ctx, "gateway.upstream:"+r.Action.Upstream)
		}
	}
	for _, g := range next.Gateways {
		if exposes(g.Default) {
			return secret.AuthorizeChange(ctx, "gateway.upstream:"+g.Default.Upstream)
		}
	}
	return nil
}
