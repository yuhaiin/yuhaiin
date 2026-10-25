package route

import (
	"context"
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// PrepareProbe applies routing/DNS policy without asking the route dialer to
// select an outbound. The caller already owns a fixed candidate Node proxy.
// Gateway interception never takes ownership of a health/measurement request.
func (s *Route) PrepareProbe(ctx context.Context, host netapi.Address) (netapi.Address, error) {
	result := s.dispatch(WithoutGateway(ctx), host)
	if result.Mode.Mode() == ModeGateway {
		return nil, &net.OpError{Op: "block", Net: host.Network(), Err: errors.New("probe cannot enter HTTP Gateway")}
	}
	if result.Mode.Mode() == ModeBlock {
		s.Push(ctx, host.Network(), host.String())
		return nil, &net.OpError{Op: "block", Net: host.Network(), Err: errors.New("probe denied by routing policy")}
	}
	return result.Addr, nil
}
