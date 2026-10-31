package inbound

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

// ProbePreparer recovers destinations and applies routing/DNS policy. It must
// retain the provided fixed Node proxy instead of choosing a route target.
type ProbePreparer func(context.Context, netapi.Address) (netapi.Address, error)

// ProbeProxy shares the existing stream/datagram governors and live shaping
// policies. Internal probes have no inbound or authenticated user identity.
func (l *Inbound) ProbeProxy(lifetime context.Context, proxy netapi.Proxy, prepare ProbePreparer) netapi.Proxy {
	return &policyProbeProxy{Proxy: proxy, control: l.handler.control, prepare: prepare, lifetime: lifetime}
}

type policyProbeProxy struct {
	paced atomic.Bool
	netapi.Proxy
	control  *trafficcontrol.Controller
	prepare  ProbePreparer
	lifetime context.Context
}

func (p *policyProbeProxy) destination(ctx context.Context, a netapi.Address) (*netapi.Context, netapi.Address, error) {
	store := netapi.WithContext(ctx)
	if previous := netapi.GetContextOrNil(ctx); previous != nil {
		store.ConnOptions().Resolver().SetMode(previous.ConnOptions().Resolver().Mode())
	}
	a, err := p.prepare(store, a)
	return store, a, err
}
func (p *policyProbeProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	store, a, err := p.destination(ctx, a)
	if err != nil {
		return nil, err
	}
	lease, ok := p.control.AdmitStream("")
	if !ok {
		return nil, errors.Join(trafficcontrol.ErrLocalLimit, ErrStreamAdmissionLimit)
	}
	c, err := p.Proxy.Conn(store, a)
	if err != nil {
		lease.Release()
		return nil, err
	}
	ruleID, _ := store.MatchedRule()
	shaped := trafficcontrol.WrapOutboundConn(p.lifetime, c, func() trafficcontrol.Policy { return p.control.Resolve("", ruleID) }, func() { p.paced.Store(true) })
	w := &probeStream{Conn: shaped, release: lease.Release}
	w.stop = context.AfterFunc(p.lifetime, w.closeTransport)
	return w, nil
}
func (p *policyProbeProxy) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	store, target, err := p.destination(ctx, a)
	if err != nil {
		return nil, err
	}
	lease, ok := p.control.AdmitDatagram()
	if !ok {
		return nil, errors.Join(trafficcontrol.ErrLocalLimit, errors.New("probe datagram session admission denied"))
	}
	c, err := p.Proxy.PacketConn(store, target)
	if err != nil {
		lease.Release()
		return nil, err
	}
	ruleID, _ := store.MatchedRule()
	w := &probePacket{PacketConn: c, ctx: p.lifetime, owner: p, release: lease.Release, policy: p.control.Resolve("", ruleID), destinations: map[string]probeDestination{a.String(): {address: target, policy: p.control.Resolve("", ruleID)}}}
	w.stop = context.AfterFunc(p.lifetime, w.closeTransport)
	return w, nil
}
func (p *policyProbeProxy) Close() error { return nil } // NodeRuntime owns the underlying client.
// HTTP may replace a pacing error with its request deadline. Such a timed-out
// full probe has ambiguous remote evidence and must not condemn the node.
func (p *policyProbeProxy) ProbeError(err error) error {
	if p.paced.Load() && err != nil {
		if e, ok := errors.AsType[net.Error](err); ok && e.Timeout() {
			return errors.Join(trafficcontrol.ErrLocalLimit, err)
		}
	}
	return err
}
func (p *policyProbeProxy) IPVersion() contractnode.IPVersion {
	if provider, ok := p.Proxy.(interface{ IPVersion() contractnode.IPVersion }); ok {
		return provider.IPVersion()
	}
	return contractnode.IPVersionAuto
}
func (p *policyProbeProxy) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported // Opaque native Ping has no byte-accounting boundary.
}

type probeStream struct {
	net.Conn
	once     sync.Once
	release  func()
	stop     func() bool
	closeErr error
}

func (c *probeStream) closeTransport() {
	c.once.Do(func() { c.closeErr = c.Conn.Close(); c.release() })
}

func (c *probeStream) Close() error {
	c.stop()
	c.closeTransport()
	return c.closeErr
}

type probeDestination struct {
	address netapi.Address
	policy  trafficcontrol.Policy
}
type probePacket struct {
	net.PacketConn
	ctx          context.Context
	owner        *policyProbeProxy
	policy       trafficcontrol.Policy
	mu           sync.Mutex
	destinations map[string]probeDestination
	once         sync.Once
	release      func()
	stop         func() bool
	closeErr     error
}

func (c *probePacket) WriteTo(b []byte, a net.Addr) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	d, ok := c.destinations[a.String()]
	if !ok {
		// STUN may contact additional mapped endpoints. Apply policy once for
		// each, without splitting the pinned UDP socket or unbounded caching.
		if len(c.destinations) >= 8 {
			c.mu.Unlock()
			return 0, trafficcontrol.ErrLocalLimit
		}
		original, err := netapi.ParseSysAddr(a)
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
		store, target, err := c.owner.destination(c.ctx, original)
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
		ruleID, _ := store.MatchedRule()
		d = probeDestination{address: target, policy: c.owner.control.Resolve("", ruleID)}
		c.destinations[a.String()] = d
	}
	c.mu.Unlock()
	if !d.policy.AllowDatagram(trafficcontrol.Upload, len(b)) {
		return 0, errors.Join(trafficcontrol.ErrLocalLimit, trafficcontrol.ErrRateLimited)
	}
	if writer, ok := c.PacketConn.(netapi.ContextPacketWriter); ok {
		return writer.WriteToContext(c.ctx, b, d.address)
	}
	return c.PacketConn.WriteTo(b, d.address)
}
func (c *probePacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(b)
	policy := c.policy
	if a != nil {
		c.mu.Lock()
		if d, ok := c.destinations[a.String()]; ok {
			policy = d.policy
		}
		c.mu.Unlock()
	}
	if (n > 0 || (err == nil && a != nil)) && !policy.AllowDatagram(trafficcontrol.Download, n) {
		return 0, nil, errors.Join(trafficcontrol.ErrLocalLimit, trafficcontrol.ErrRateLimited)
	}
	return n, a, err
}
func (c *probePacket) Close() error {
	c.stop()
	c.closeTransport()
	return c.closeErr
}
func (c *probePacket) closeTransport() {
	c.once.Do(func() { c.closeErr = c.PacketConn.Close(); c.release() })
}
