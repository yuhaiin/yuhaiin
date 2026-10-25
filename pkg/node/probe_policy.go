package node

import (
	"context"
	"errors"
	"net"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

var errProbePolicyUnavailable = errors.New("probe routing and traffic policy is not ready")

func localProbeDenial(err error) bool {
	return errors.Is(err, errProbePolicyUnavailable) || errors.Is(err, trafficcontrol.ErrLocalLimit) || netapi.IsBlockError(err)
}

type RuntimeOption func(*NodeRuntime)

// RequireProbePolicy gates network probes until application routing and traffic
// control have been hydrated. Standalone/core runtimes keep their existing API.
func RequireProbePolicy() RuntimeOption { return func(r *NodeRuntime) { r.requireProbePolicy = true } }

type ProbePolicy struct {
	// Ready is a nonblocking snapshot read; it must not call back into NodeRuntime.
	Ready func() bool
	Wrap  func(context.Context, netapi.Proxy) netapi.Proxy
}

func classifyProbeError(proxy netapi.Proxy, err error) error {
	if classifier, ok := proxy.(interface{ ProbeError(error) error }); ok {
		return classifier.ProbeError(err)
	}
	return err
}

func (r *NodeRuntime) probePolicyState() string {
	b := r.probePolicy.Load()
	if b == nil {
		if r.requireProbePolicy {
			return "waiting"
		}
		return "standalone"
	}
	if b.Ready != nil && !b.Ready() {
		return "waiting"
	}
	return "enforced"
}

func (r *NodeRuntime) SetProbePolicy(policy ProbePolicy) {
	if policy.Wrap == nil {
		r.probePolicy.Store(nil)
		return
	}
	r.probePolicy.Store(new(policy))
}
func (r *NodeRuntime) probePolicyReady() bool {
	b := r.probePolicy.Load()
	if b == nil {
		return !r.requireProbePolicy
	}
	return b.Ready == nil || b.Ready()
}
func (r *NodeRuntime) probeDialer(ctx context.Context, id string, n contract.Node, epoch uint64, health bool) (netapi.Proxy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b := r.probePolicy.Load()
	if (b == nil && r.requireProbePolicy) || (b != nil && b.Ready != nil && !b.Ready()) {
		return nil, errProbePolicyUnavailable
	}
	p, err := r.getContractDialer(ctx, id, n, epoch)
	if err != nil {
		return nil, err
	}
	if health {
		if observed, ok := p.(*observedProxy); ok {
			p = &healthProbeProxy{observed}
		}
	}
	if b != nil {
		p = b.Wrap(ctx, p)
	}
	return p, nil
}

// A complete active probe is one outcome. Primitive connect/first-response
// observations still update traffic counters, but cannot double-count recovery.
type healthProbeProxy struct{ *observedProxy }

func (p *healthProbeProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	return p.conn(ctx, a, true)
}
func (p *healthProbeProxy) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	return p.packetConn(ctx, a, true)
}
