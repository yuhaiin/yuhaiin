package route

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// SetTrafficAccess installs the optional authorization capability before serving
// ingress. Policy activation updates that capability without rebuilding routes.
func (s *Route) SetTrafficAccess(access netapi.TrafficAccess) { s.access = access }

func (s *Route) authorizeDispatch(ctx context.Context, original, target netapi.Address) (netapi.Address, error) {
	actual, err := netapi.PinTrafficTarget(ctx, s.access, original, target)
	if err != nil {
		return nil, err
	}
	if session := netapi.TrafficAccessSessionFromContext(ctx); session != nil && netapi.TrafficSubjectFromContext(ctx).External {
		if err := session.Authorize(original, actual); err != nil {
			return nil, err
		}
	}
	return actual, nil
}

type authorizedProxy struct {
	netapi.Proxy
	access           netapi.TrafficAccess
	subject          netapi.TrafficSubject
	original, actual netapi.Address
}

func (p *authorizedProxy) Conn(ctx context.Context, address netapi.Address) (net.Conn, error) {
	// An explicit outbound selection is only usable for the destination and
	// authenticated subject that were checked before Gateway pool lookup.
	if !sameRouteAddress(address, p.actual) || netapi.TrafficSubjectFromContext(ctx) != p.subject {
		return nil, netapi.ErrTrafficAccessDenied
	}
	return netapi.DialTraffic(ctx, p.access, p.original, p.actual, p.Proxy.Conn)
}
func (p *authorizedProxy) ConnectionPoolIdentity() string { return netapi.ProxyIdentity(p.Proxy) }
