package route

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type skipGatewayKey struct{}
type preparedTCPKey struct{}

// preparedTCP pins the ordinary routing decision made by the inbound gate. Its
// owner check prevents a forked HTTP request or dial attempt reusing that result.
type preparedTCP struct {
	router *Route
	owner  *netapi.Context
	input  netapi.Address
	result routeResult
}

// WithoutGateway evaluates normal L4 rules for a Gateway's outgoing requests.
// Only Gateway actions are skipped: block rules and loop detection still run.
func WithoutGateway(ctx context.Context) context.Context {
	if skipGateway(ctx) {
		return ctx
	}
	return context.WithValue(ctx, skipGatewayKey{}, true)
}
func skipGateway(ctx context.Context) bool {
	skip, _ := ctx.Value(skipGatewayKey{}).(bool)
	return skip
}

// SetGatewayHandler connects the existing Route to an HTTP stream handler at
// startup. Destination recovery follows the same FakeIP/hosts chain as Conn.
func (s *Route) SetGatewayHandler(recoverDestination func(context.Context, netapi.Address) netapi.Address, handle func(*netapi.Context, *netapi.StreamMeta, string) bool) {
	s.gatewayRecovery = recoverDestination
	s.gatewayHandler = handle
}

// Intercept is the optional common inbound hook. With no Gateway routing rules
// it does no lookup, allocation or stream read. Otherwise normal rule order
// determines whether a Gateway receives the connection at all.
func (s *Route) Intercept(ctx *netapi.Context, meta *netapi.StreamMeta) bool {
	if s.gatewayHandler == nil || !s.ms.hasGateway.Load() || skipGateway(ctx) {
		return false
	}
	address := meta.Address
	if s.gatewayRecovery != nil {
		address = s.gatewayRecovery(ctx, address)
	}
	if s.access != nil {
		if err := s.access.Preflight(netapi.TrafficSubjectFromContext(ctx)); err != nil {
			_ = meta.Src.Close()
			return true
		}
	}
	decide := func() (routeResult, bool) {
		matchCtx, cancel := context.WithTimeout(ctx, configuration.Timeout)
		defer cancel()
		result := s.dispatch(matchCtx, address)
		return result, matchCtx.Err() == nil
	}
	result, ok := decide()
	if !ok {
		if meta.Src != nil {
			_ = meta.Src.Close()
		}
		return true
	}
	if result.Mode.Mode() == ModeGateway {
		if s.access != nil {
			actual, err := netapi.PinTrafficTarget(ctx, s.access, address, result.Addr)
			if err != nil {
				_ = meta.Src.Close()
				return true
			}
			conn, err := netapi.BindTrafficConn(ctx, s.access, address, actual, meta.Src)
			if err != nil {
				_ = meta.Src.Close()
				return true
			}
			meta.Src = conn
		}
		ctx.Context = WithoutGateway(ctx.Context)
		if s.gatewayHandler(ctx, meta, result.Mode.Target().ID) {
			return true
		}
		// Non-HTTP, excluded and unsupported TLS traffic continues through the next
		// normal routing action. Do not feed it back into the selected Gateway.
		result, ok = decide()
		if !ok {
			if meta.Src != nil {
				_ = meta.Src.Close()
			}
			return true
		}
	}
	ctx.Context = context.WithValue(ctx.Context, preparedTCPKey{}, preparedTCP{router: s, owner: ctx, input: address, result: result})
	return false
}

func sameRouteAddress(a, b netapi.Address) bool {
	if a.Network() != b.Network() || a.IsFqdn() != b.IsFqdn() || a.Port() != b.Port() {
		return false
	}
	if !a.IsFqdn() {
		return a.(netapi.IPAddress).AddrPort() == b.(netapi.IPAddress).AddrPort()
	}
	return a.Hostname() == b.Hostname()
}
