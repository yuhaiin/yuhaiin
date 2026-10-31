package node

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/apernet/quic-go"
)

func testCircuitRules() circuitRules {
	return circuitRules{failures: 3, recovery: 2, minSamples: 4, failureRate: .75, maxAge: time.Minute, cooldown: 30 * time.Second, trialTimeout: 10 * time.Second, concurrency: 1, maxRequests: 4}
}
func circuitSample(h *contract.ChannelHealth, ok bool) {
	h.Sequence++
	h.Samples = append(h.Samples, contract.HealthSample{Sequence: h.Sequence, At: time.Now().UnixMilli(), OK: ok, Kind: "connect"})
}

func TestCircuitTransitionsAndBoundedRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newCircuitBreaker(testCircuitRules(), nil)
		h := contract.ChannelHealth{}
		for range 3 {
			circuitSample(&h, false)
			b.observe(h, time.Now())
		}
		if state := b.snapshot(time.Now()); state.State != "open" || state.Reason != "consecutive_failures" {
			t.Fatal(state)
		}
		if _, ok := b.tryAcquire(t.Context(), time.Now()); ok {
			t.Fatal("open circuit admitted")
		}
		time.Sleep(30 * time.Second)
		first, ok := b.tryAcquire(t.Context(), time.Now())
		if !ok {
			t.Fatal("no half-open permit")
		}
		if _, ok := b.tryAcquire(t.Context(), time.Now()); ok {
			t.Fatal("half-open concurrency exceeded")
		}
		circuitSample(&h, true)
		b.observe(h, time.Now())
		first.finish()
		if state := b.snapshot(time.Now()); state.State != "half_open" || state.Recovered != 1 {
			t.Fatal(state)
		}
		second, ok := b.tryAcquire(t.Context(), time.Now())
		if !ok {
			t.Fatal("second recovery request blocked")
		}
		circuitSample(&h, true)
		b.observe(h, time.Now())
		second.finish()
		if state := b.snapshot(time.Now()); state.State != "closed" || state.Reason != "recovered" || state.InFlight != 0 {
			t.Fatal(state)
		}
		if p, ok := b.tryAcquire(t.Context(), time.Now()); !ok || p != nil {
			t.Fatal("closed fast path allocated a permit")
		}
	})
}
func TestCircuitFiniteQuotaCancellationTimeoutAndEpochs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newCircuitBreaker(testCircuitRules(), nil)
		h := contract.ChannelHealth{}
		for range 3 {
			circuitSample(&h, false)
			b.observe(h, time.Now())
		}
		time.Sleep(30 * time.Second)
		for range 4 {
			ctx, cancel := context.WithCancel(t.Context())
			p, ok := b.tryAcquire(ctx, time.Now())
			if !ok {
				t.Fatal("quota exhausted early")
			}
			cancel()
			synctest.Wait()
			p.finish()
		}
		if _, ok := b.tryAcquire(t.Context(), time.Now()); ok {
			t.Fatal("unbounded cancelled half-open requests")
		}
		time.Sleep(10 * time.Second)
		if state := b.snapshot(time.Now()); state.State != "open" || state.Reason != "trial_timeout" {
			t.Fatal(state)
		}
		time.Sleep(30 * time.Second)
		old, ok := b.tryAcquire(t.Context(), time.Now())
		if !ok {
			t.Fatal("new trial cycle blocked")
		}
		circuitSample(&h, false)
		b.observe(h, time.Now())
		time.Sleep(30 * time.Second)
		current, ok := b.tryAcquire(t.Context(), time.Now())
		if !ok {
			t.Fatal("new cycle blocked")
		}
		old.finish()
		if state := b.snapshot(time.Now()); state.InFlight != 1 {
			t.Fatal("old epoch released new permit", state)
		}
		current.finish()
	})
}
func TestCircuitFailureRateAndIgnoredOutcomes(t *testing.T) {
	b := newCircuitBreaker(testCircuitRules(), nil)
	b.rules.failureRate = .5
	h := contract.ChannelHealth{}
	for _, ok := range []bool{true, false, true, false} {
		circuitSample(&h, ok)
		b.observe(h, time.Now())
	}
	if state := b.snapshot(time.Now()); state.State != "open" || state.Reason != "failure_rate" {
		t.Fatal(state)
	}
	for _, err := range []error{context.Canceled, io.EOF, net.ErrClosed, errors.New("quota denied"), &net.OpError{Op: "block", Err: errors.New("access policy")}, &quic.StreamError{ErrorCode: 0}, &quic.ApplicationError{ErrorCode: 0}, &quic.TransportError{ErrorCode: quic.NoError}} {
		if healthFailure(err) {
			t.Fatal("normal/policy outcome condemned node", err)
		}
	}
	if !healthFailure(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}) {
		t.Fatal("network refusal ignored")
	}
	if circuitIOFailure(context.DeadlineExceeded) {
		t.Fatal("application I/O timeout condemned node")
	}
}

type failingCircuitProxy struct {
	netapi.Proxy
	fail  atomic.Bool
	calls atomic.Int32
}

func (p *failingCircuitProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	p.calls.Add(1)
	if p.fail.Load() {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}
func (*failingCircuitProxy) Close() error { return nil }

func TestAutomaticSelectorCachedProxyFailsOverWithoutReplayAndRecovers(t *testing.T) {
	r := newTestRuntime(t)
	for _, id := range []string{"a", "b"} {
		if _, err := r.Save(t.Context(), testNode(t, id, id)); err != nil {
			t.Fatal(err)
		}
		r.observer.counter(id).remoteEvidence(true, contract.HealthSample{OK: true, Kind: "connect"}, nil)
	}
	a, b := new(failingCircuitProxy), new(failingCircuitProxy)
	a.fail.Store(true)
	for id, p := range map[string]*failingCircuitProxy{"a": a, "b": b} {
		if _, err := r.proxies.LoadOrCreate(t.Context(), id, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: p, Name: id}, nil }); err != nil {
			t.Fatal(err)
		}
	}
	selector, err := NewSelectorService(r).Save(t.Context(), contract.Selector{Name: "Resilient", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "failover", ReturnToPreferred: true, MinHoldMS: 1, CooldownMS: 1, MaxFailureRate: .95, Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}, {NodeID: "b", Enabled: true, Priority: 1, Weight: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := r.GetTarget(t.Context(), "tcp", "proxy", contractroute.Target{Type: "selector", ID: selector.ID})
	if err != nil {
		t.Fatal(err)
	}
	address, _ := netapi.ParseAddress("tcp", "example.invalid:443")
	for range 3 {
		if _, err := outbound.Conn(t.Context(), address); err == nil {
			t.Fatal("failed request silently replayed")
		}
	}
	if a.calls.Load() != 3 || b.calls.Load() != 0 {
		t.Fatal("transport attempt replayed", a.calls.Load(), b.calls.Load())
	}
	conn, err := outbound.Conn(t.Context(), address)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if a.calls.Load() != 3 || b.calls.Load() != 1 {
		t.Fatal("cached selector did not fail over", a.calls.Load(), b.calls.Load())
	}
	a.fail.Store(false)
	r.selectors.mu.Lock()
	breaker := r.selectors.circuitBindings[selector.ID]["a"].tcp
	breaker.mu.Lock()
	breaker.openUntil = time.Now().Add(-time.Second)
	breaker.mu.Unlock()
	r.selectors.rebuild(time.Now().Add(time.Second))
	r.selectors.mu.Unlock()
	for range 2 {
		c, err := outbound.Conn(t.Context(), address)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	if state := breaker.snapshot(time.Now()); state.State != "closed" {
		t.Fatal(state)
	}
	if a.calls.Load() != 5 {
		t.Fatal("preferred node not recovered", a.calls.Load())
	}
}

func TestNodeConfigurationGenerationRejectsOldPlansAndEvidence(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "a", "a")
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	oldProxy, err := r.GetDialerByID(t.Context(), n.ID)
	if err != nil {
		t.Fatal(err)
	}
	oldPlan := r.selectors.snapshot.Load()
	epoch := oldPlan.generations[n.ID]
	n.IPVersion = contract.IPVersionIPv4
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	current, err := r.GetDialerByID(t.Context(), n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.getContractDialer(t.Context(), n.ID, oldPlan.nodes[n.ID], epoch); !errors.Is(err, errNodeReconfigured) {
		t.Fatal("old config poisoned cache", err)
	}
	oldProxy.(*observedProxy).recordEvidence(true, contract.HealthSample{Kind: "connect", OK: true}, nil)
	if h := r.observer.counter(n.ID).snapshot().TCPHealth; len(h.Samples) != 0 {
		t.Fatal("old connection supplied new-config health", h)
	}
	current.(*observedProxy).recordEvidence(true, contract.HealthSample{Kind: "connect", OK: true}, nil)
	if h := r.observer.counter(n.ID).snapshot().TCPHealth; len(h.Samples) != 1 {
		t.Fatal(h)
	}
	before, _ := r.proxies.store.Load(n.ID)
	generation := r.observer.counter(n.ID).generation.Load()
	n.Name = "Renamed"
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	after, _ := r.proxies.store.Load(n.ID)
	if after != before || after.Name != "Renamed" || r.observer.counter(n.ID).generation.Load() != generation {
		t.Fatal("rename evicted transport or measurements")
	}
}

type udpCircuitProxy struct {
	netapi.Proxy
	packet *udpCircuitPacket
}

func (p *udpCircuitProxy) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return p.packet, nil
}
func (*udpCircuitProxy) Close() error { return nil }

type udpCircuitPacket struct{ net.PacketConn }

func (*udpCircuitPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	return copy(b, "reply"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}, nil
}
func (*udpCircuitPacket) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (*udpCircuitPacket) Close() error                              { return nil }

func TestUDPHalfOpenNeedsReplyAndPinsExistingSession(t *testing.T) {
	r := newTestRuntime(t)
	for _, id := range []string{"a", "b"} {
		if _, err := r.Save(t.Context(), testNode(t, id, id)); err != nil {
			t.Fatal(err)
		}
		r.observer.counter(id).remoteEvidence(false, contract.HealthSample{Kind: "reply", OK: true}, nil)
	}
	for _, id := range []string{"a", "b"} {
		p := &udpCircuitProxy{packet: new(udpCircuitPacket)}
		if _, err := r.proxies.LoadOrCreate(t.Context(), id, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: p, Name: id}, nil }); err != nil {
			t.Fatal(err)
		}
	}
	saved, err := NewSelectorService(r).Save(t.Context(), contract.Selector{Name: "UDP trials", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "failover", ReturnToPreferred: true, MinHoldMS: 1, CooldownMS: 1, MaxFailureRate: .95, Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}, {NodeID: "b", Enabled: true, Weight: 1, Priority: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	circuit := r.selectors.circuitBindings[saved.ID]["a"].udp
	for range 3 {
		r.observer.counter("a").remoteEvidence(false, contract.HealthSample{Kind: "io"}, &net.OpError{Op: "read", Err: syscall.ECONNRESET})
	}
	circuit.mu.Lock()
	circuit.openUntil = time.Now().Add(-time.Second)
	circuit.mu.Unlock()
	r.selectors.mu.Lock()
	r.selectors.rebuild(time.Now().Add(time.Second))
	r.selectors.mu.Unlock()
	proxy, err := r.GetTarget(t.Context(), "udp", "proxy", contractroute.Target{Type: "selector", ID: saved.ID})
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := netapi.ParseAddress("udp", "192.0.2.1:53")
	conn, err := proxy.PacketConn(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if state := circuit.snapshot(time.Now()); state.Recovered != 0 || state.InFlight != 1 {
		t.Fatal("UDP creation claimed recovery", state)
	}
	if _, err := conn.WriteTo([]byte("query"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
	if state := circuit.snapshot(time.Now()); state.Recovered != 0 {
		t.Fatal("UDP send claimed remote reply", state)
	}
	if _, _, err := conn.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if state := circuit.snapshot(time.Now()); state.Recovered != 1 || state.InFlight != 0 {
		t.Fatal(state)
	}
	// An established PacketConn keeps its node even while another candidate is
	// chosen for future sessions. Writes do not re-enter selector admission.
	circuit.mu.Lock()
	circuit.open(time.Now(), "recovery_failure")
	circuit.mu.Unlock()
	if _, err := conn.WriteTo([]byte("still pinned"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); err != nil {
		t.Fatal(err)
	}
}

func TestCircuitRecoveryDoesNotDoubleCountTCPResponse(t *testing.T) {
	b := newCircuitBreaker(testCircuitRules(), nil)
	h := contract.ChannelHealth{}
	b.mu.Lock()
	b.openUntil = time.Now().Add(-time.Second)
	b.transition(circuitOpen, "consecutive_failures")
	b.mu.Unlock()
	p, ok := b.tryAcquire(t.Context(), time.Now())
	if !ok {
		t.Fatal("trial blocked")
	}
	defer p.finish()
	circuitSample(&h, true)
	b.observe(h, time.Now())
	circuitSample(&h, true)
	h.Samples[len(h.Samples)-1].Kind = "response"
	b.observe(h, time.Now())
	if state := b.snapshot(time.Now()); state.State != "half_open" || state.Recovered != 1 {
		t.Fatal("one TCP connection counted twice", state)
	}
}

func TestCircuitTrialDeadlineCancelsUnderlyingOperation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := newCircuitBreaker(testCircuitRules(), nil)
		b.mu.Lock()
		b.openUntil = time.Now().Add(-time.Second)
		b.transition(circuitOpen, "consecutive_failures")
		b.mu.Unlock()
		permit, ok := b.tryAcquire(t.Context(), time.Now())
		if !ok {
			t.Fatal("trial blocked")
		}
		done := make(chan error, 1)
		go func() {
			_, err := (&circuitPermitProxy{Proxy: deadlineCircuitProxy{}, permit: permit}).Conn(t.Context(), nil)
			done <- err
		}()
		synctest.Wait()
		time.Sleep(10 * time.Second)
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if state := b.snapshot(time.Now()); state.InFlight != 0 {
			t.Fatal(state)
		}
	})
}

type deadlineCircuitProxy struct{ netapi.Proxy }

func (deadlineCircuitProxy) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRecreatedNodeIDRejectsPreviousConfiguration(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "reused", "old")
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	old := r.selectors.snapshot.Load()
	if err := r.Remove(t.Context(), n.ID); err != nil {
		t.Fatal(err)
	}
	n.Name = "new"
	n.IPVersion = contract.IPVersionIPv4
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	if _, err := r.getContractDialer(t.Context(), n.ID, old.nodes[n.ID], old.generations[n.ID]); !errors.Is(err, errNodeReconfigured) {
		t.Fatal("recreated ID accepted old transport", err)
	}
}

type emptyReplyPacket struct{ net.PacketConn }

func (emptyReplyPacket) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}, nil
}
func (emptyReplyPacket) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func TestUDPEmptyDatagramIsRemoteEvidence(t *testing.T) {
	c := new(nodeCounters)
	packet := &observedPacketConn{PacketConn: emptyReplyPacket{}, c: c}
	if _, _, err := packet.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.WriteTo(nil, &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	if h := c.snapshot().UDPHealth; len(h.Samples) != 1 || !h.Samples[0].OK {
		t.Fatal(h)
	}
	if c.udpReceived.Load() != 1 || c.udpSent.Load() != 1 {
		t.Fatal("empty datagrams not counted")
	}
}

func TestInheritedRecoveryThresholdCannotExceedTrialQuota(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	_, err := NewSelectorService(r).Save(t.Context(), contract.Selector{Name: "Inherited thresholds", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "failover", Circuit: &contract.CircuitConfig{HalfOpenMaxRequests: 4}, Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := r.Monitoring(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	changed := before.Config
	changed.Probe.RecoveryThreshold = 5
	if _, err := r.SaveMonitoring(t.Context(), changed); err == nil {
		t.Fatal("accepted impossible half-open recovery quota")
	}
	after, err := r.Monitoring(t.Context())
	if err != nil || after.Config.Revision != before.Config.Revision {
		t.Fatal("rejected settings changed persistent defaults", err)
	}
}
