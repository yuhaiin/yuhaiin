package node

import (
	"context"
	"errors"
	"net"
	"slices"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type circuitKey struct {
	nodeID     string
	generation uint64
	tcp        bool
	rules      circuitRules
}
type nodeCircuits struct{ tcp, udp *circuitBreaker }
type nodeCircuitListeners struct{ tcp, udp []*circuitBreaker }

func (s *selectorRuntime) circuitRules(p contract.SelectorPolicy) circuitRules {
	p = p.Effective()
	probe := s.defaults.Probe
	if p.Probe != nil {
		probe = p.Probe.Effective()
	}
	cfg := contract.CircuitConfig{}
	if p.Circuit != nil {
		cfg = *p.Circuit
	}
	cfg = cfg.Effective(p.RecoveryThreshold, probe.CooldownMS)
	return circuitRules{failures: p.FailureThreshold, recovery: p.RecoveryThreshold, minSamples: p.MinSamples, failureRate: p.MaxFailureRate, maxAge: time.Duration(p.MaxAgeMS) * time.Millisecond, cooldown: time.Duration(cfg.CooldownMS) * time.Millisecond, trialTimeout: time.Duration(cfg.TrialTimeoutMS) * time.Millisecond, concurrency: cfg.HalfOpenConcurrency, maxRequests: cfg.HalfOpenMaxRequests}
}
func (s *selectorRuntime) wakeCircuit() {
	select {
	case s.circuitWake <- struct{}{}:
	default:
	}
}

// Bindings reuse a state machine when selectors share the same Node/channel
// and thresholds. Observations remain owned by nodeCounters, not the breaker.
func (s *selectorRuntime) prepareCircuits() {
	next := make(map[circuitKey]*circuitBreaker)
	bindings := make(map[string]map[string]nodeCircuits)
	listeners := make(map[string]*nodeCircuitListeners)
	for _, config := range s.configs {
		config = s.effectivePolicy(config)
		if config.Policy == nil {
			continue
		}
		p := config.Policy.Effective()
		if p.Mode == "manual" || p.Locked || (p.Circuit != nil && p.Circuit.Disabled) {
			continue
		}
		bindings[config.ID] = make(map[string]nodeCircuits)
		for _, candidate := range p.Candidates {
			if !candidate.Enabled || !s.nodes[candidate.NodeID].Enabled {
				continue
			}
			pair := nodeCircuits{}
			for _, tcp := range []bool{true, false} {
				key := circuitKey{nodeID: candidate.NodeID, generation: s.nodeGenerations[candidate.NodeID], tcp: tcp, rules: s.circuitRules(p)}
				b := next[key]
				if b == nil {
					b = s.breakers[key]
				}
				if b == nil {
					b = newCircuitBreaker(key.rules, s.wakeCircuit)
				}
				next[key] = b
				l := listeners[candidate.NodeID]
				if l == nil {
					l = new(nodeCircuitListeners)
					listeners[candidate.NodeID] = l
				}
				if tcp {
					pair.tcp = b
					if !slices.Contains(l.tcp, b) {
						l.tcp = append(l.tcp, b)
					}
				} else {
					pair.udp = b
					if !slices.Contains(l.udp, b) {
						l.udp = append(l.udp, b)
					}
				}
			}
			bindings[config.ID][candidate.NodeID] = pair
		}
	}
	// Include old counters when removing the last binding so they stop notifying
	// orphaned circuit state while existing streams continue to transfer bytes.
	for id, c := range s.circuitCounters {
		if listeners[id] == nil {
			c.setCircuitListeners(nil)
		}
	}
	counters := make(map[string]*nodeCounters, len(listeners))
	for id, l := range listeners {
		if c := s.counters[id]; c != nil {
			c.setCircuitListeners(l)
			counters[id] = c
		}
	}
	s.breakers, s.circuitBindings, s.circuitCounters = next, bindings, counters
}
func (n *nodeCounters) setCircuitListeners(listeners *nodeCircuitListeners) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.circuitListeners.Store(listeners)
	if listeners == nil {
		return
	}
	now := time.Now()
	for _, b := range listeners.tcp {
		b.observe(n.tcpHealth, now)
	}
	for _, b := range listeners.udp {
		b.observe(n.udpHealth, now)
	}
}
func normalizeHealthSequence(h *contract.ChannelHealth) {
	if h.Sequence != 0 || len(h.Samples) == 0 {
		return
	}
	for i := range h.Samples {
		h.Samples[i].Sequence = uint64(i + 1)
	}
	h.Sequence = uint64(len(h.Samples))
}

// Only a Half-open recovery trial needs a wrapper or permit allocation.
// No attempt is replayed after a transport call returns an error.
type circuitPermitProxy struct {
	netapi.Proxy
	permit *circuitPermit
}

func (p *circuitPermitProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	defer p.permit.finish()
	return p.Proxy.Conn(p.permit.ctx, a)
}
func (p *circuitPermitProxy) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	// Bound session creation, but keep its parent context after construction.
	// Finishing a recovery lease must not cancel an established UDP session.
	creationCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.permit.ctx, cancel)
	conn, err := p.Proxy.PacketConn(creationCtx, a)
	stop()
	if err != nil {
		cancel()
		p.permit.finish()
		return nil, err
	}
	return &circuitTrialPacketConn{PacketConn: conn, permit: p.permit, cancel: cancel}, nil
}
func (p *circuitPermitProxy) Ping(ctx context.Context, a netapi.Address) (uint64, error) {
	defer p.permit.finish()
	return p.Proxy.Ping(p.permit.ctx, a)
}
func (p *circuitPermitProxy) IPVersion() contract.IPVersion {
	if v, ok := p.Proxy.(interface{ IPVersion() contract.IPVersion }); ok {
		return v.IPVersion()
	}
	return contract.IPVersionAuto
}

type circuitTrialPacketConn struct {
	net.PacketConn
	permit *circuitPermit
	cancel context.CancelFunc
}

func (c *circuitTrialPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(b)
	if n > 0 || a != nil || err != nil {
		c.permit.finish()
	}
	return n, a, err
}
func (c *circuitTrialPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, a)
	if err != nil {
		c.permit.finish()
	}
	return n, err
}
func (c *circuitTrialPacketConn) Close() error {
	c.permit.finish()
	c.cancel()
	return c.PacketConn.Close()
}

func circuitIOFailure(err error) bool {
	if !healthFailure(err) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if e, ok := errors.AsType[net.Error](err); ok && e.Timeout() {
		return false
	}
	return true
}

// automaticSelectorProxy can be cached by a caller: admission occurs once per
// new stream/session, never per packet and never again for an established flow.
type automaticSelectorProxy struct {
	netapi.EmptyDispatch
	runtime *selectorRuntime
	id      string
}

func (p *automaticSelectorProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	d, err := p.runtime.acquireTarget(ctx, "tcp", p.id)
	if err != nil {
		return nil, err
	}
	return d.Conn(ctx, a)
}
func (p *automaticSelectorProxy) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	d, err := p.runtime.acquireTarget(ctx, "udp", p.id)
	if err != nil {
		return nil, err
	}
	return d.PacketConn(ctx, a)
}
func (p *automaticSelectorProxy) Ping(ctx context.Context, a netapi.Address) (uint64, error) {
	d, err := p.runtime.acquireTarget(ctx, "udp", p.id)
	if err != nil {
		return 0, err
	}
	return d.Ping(ctx, a)
}
func (p *automaticSelectorProxy) Close() error { return nil }
