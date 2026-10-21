package app

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
)

// selectedGatewayProxy enters ordinary connection/traffic accounting after the
// request's route decision, so pooling cannot select an outbound a second time.
type selectedGatewayProxy struct {
	netapi.Proxy
	connections *statistics.Connections
	fakeDNS     *resolver.Fakedns
}

func (p selectedGatewayProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	return p.fakeDNS.ConnWithLease(ctx, a, func() (net.Conn, error) {
		return p.connections.ConnWithProxy(ctx, a, p.Proxy)
	})
}
