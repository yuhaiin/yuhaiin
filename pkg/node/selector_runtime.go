package node

import (
	"context"
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"golang.org/x/time/rate"
	"io"
	"math/rand/v2"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type preparedSelector struct {
	generations            map[string]uint64
	circuits               map[string]nodeCircuits
	tcpOrder, udpOrder     []string
	config                 contract.Selector
	nodes                  map[string]contract.Node
	status                 contract.SelectorRuntimeStatus
	tcpWeights, udpWeights []weightedChoice
	tcpTotal, udpTotal     uint64
}

type selectorSnapshot struct {
	metrics      selectionMetricSnapshot
	items        map[string]*preparedSelector
	nodes        map[string]contract.Node
	generations  map[string]uint64
	tcpID, udpID string
}

// selectorRuntime has one worker per core instance. Connection creation reads
// immutable snapshots, with neither database access nor ranking on the hot path.
type selectorRuntime struct {
	nodeGenerations    map[string]uint64
	tcpID, udpID       string
	breakers           map[circuitKey]*circuitBreaker
	circuitBindings    map[string]map[string]nodeCircuits
	circuitCounters    map[string]*nodeCounters
	circuitWake        chan struct{}
	networkMonitor     io.Closer
	interfaceName      atomic.Pointer[string]
	networkWake        chan struct{}
	scheduler          *probeScheduler
	monitorStore       *plainstore.MonitoringStore
	defaults           contract.MonitoringConfig
	network            contract.MonitoringNetworkState
	platform           string
	probeLimiter       *rate.Limiter
	probeRateOverrides map[int64]*rate.Limiter
	runtime            *NodeRuntime
	store              *plainstore.SelectorStore
	mu                 sync.Mutex
	configs            []contract.Selector
	nodes              map[string]contract.Node
	counters           map[string]*nodeCounters
	snapshot           atomic.Pointer[selectorSnapshot]
	stop               chan struct{}
	done               chan struct{}
}

func newSelectorRuntime(ctx context.Context, r *NodeRuntime, nodes *plainstore.NodeStore) (*selectorRuntime, error) {
	s := &selectorRuntime{circuitWake: make(chan struct{}, 1), networkWake: make(chan struct{}, 1), scheduler: newProbeScheduler(), monitorStore: plainstore.NewMonitoringStore(r.sqlite.DB()), network: defaultMonitoringNetwork(), platform: runtime.GOOS, runtime: r, store: plainstore.NewSelectorStore(r.sqlite.DB()), stop: make(chan struct{}), done: make(chan struct{})}
	if err := s.reload(ctx, nodes); err != nil {
		s.scheduler.close()
		return nil, err
	}
	s.networkMonitor = interfaces.AddNetworkMonitor(s.interfaceChanged)
	go s.run()
	return s, nil
}

func (s *selectorRuntime) reload(ctx context.Context, store *plainstore.NodeStore) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	configs, err := s.store.List(ctx)
	if err != nil {
		return err
	}
	nodes, err := store.List(ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]contract.Node, len(nodes))
	counters := make(map[string]*nodeCounters, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
		s.runtime.observer.counter(n.ID)
	}
	for _, c := range configs {
		if c.Policy != nil {
			for _, candidate := range c.Policy.Candidates {
				counters[candidate.NodeID] = s.runtime.observer.counter(candidate.NodeID)
			}
		}
	}
	defaults, err := s.monitorStore.Get(ctx)
	if err != nil {
		return err
	}
	if s.probeLimiter == nil || s.defaults.Probe.MaxProbeBandwidth != defaults.Probe.MaxProbeBandwidth {
		if s.probeLimiter != nil {
			s.scheduler.replace(nil, defaults.Probe.Concurrency)
		}
		s.probeLimiter = newProbeLimiter(defaults.Probe.MaxProbeBandwidth)
	}
	s.defaults = defaults
	s.runtime.measurementLimit.Store(int32(defaults.Probe.Concurrency))
	selection, err := store.Selection(ctx)
	if err != nil {
		return err
	}
	s.tcpID, s.udpID = "", ""
	if selection.TCP != nil {
		s.tcpID = selection.TCP.ID
	}
	if selection.UDP != nil {
		s.udpID = selection.UDP.ID
	}
	s.nodeGenerations = s.runtime.observer.generations()
	s.configs, s.nodes, s.counters = configs, byID, counters
	s.prepareCircuits()
	s.scheduleLocked()
	s.rebuild(time.Now())
	return nil
}

func (s *selectorRuntime) run() {
	defer close(s.done)
	defer s.networkMonitor.Close()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-s.circuitWake:
			s.mu.Lock()
			s.rebuild(time.Now())
			s.mu.Unlock()
		case <-s.networkWake:
			s.reconcileInterface()
		case now := <-ticker.C:
			s.mu.Lock()
			// No SQLite traffic, proxy construction, or network traffic while idle.
			if slices.ContainsFunc(s.configs, func(c contract.Selector) bool {
				return c.Policy != nil && c.Policy.Effective().Mode != "manual" && !c.Policy.Locked
			}) {
				s.rebuild(now)
			}
			s.mu.Unlock()
		}
	}
}

func (s *selectorRuntime) rebuild(now time.Time) {
	previous := s.snapshot.Load()
	unavailable := s.runtime.nativeSelectionUnavailable(now)
	next := &selectorSnapshot{nodes: s.nodes, generations: s.nodeGenerations, tcpID: s.tcpID, udpID: s.udpID, items: make(map[string]*preparedSelector, len(s.configs))}
	for _, config := range s.configs {
		config = s.effectivePolicy(config)
		p := &preparedSelector{generations: s.nodeGenerations, circuits: s.circuitBindings[config.ID], config: config, nodes: make(map[string]contract.Node), status: contract.SelectorRuntimeStatus{ID: config.ID, Revision: config.Revision, Events: []contract.SelectorEvent{}}}
		if previous != nil {
			if old := previous.items[config.ID]; old != nil {
				p.status = old.status
				p.status.Revision = config.Revision
			}
		}
		p.nodes[config.NodeID] = s.nodes[config.NodeID]
		var tcp, udp []selectionInput
		if config.Policy != nil {
			for _, c := range config.Policy.Candidates {
				n, exists := s.nodes[c.NodeID]
				p.nodes[c.NodeID] = n
				counter := s.counters[c.NodeID]
				if counter == nil {
					continue
				}
				stats := counter.snapshot()
				input := selectionInput{unavailableReason: unavailable[c.NodeID], config: c, enabled: exists && n.Enabled, health: stats.TCPHealth, speed: stats.Throughput, active: counter.activeTCP.Load() + counter.activeUDP.Load()}
				if b := p.circuits[c.NodeID].tcp; b != nil {
					b.observe(stats.TCPHealth, now)
					state := b.snapshot(now)
					input.circuit = &state
				}
				tcp = append(tcp, input)
				input.health = stats.UDPHealth
				input.udp = true
				input.circuit = nil
				if b := p.circuits[c.NodeID].udp; b != nil {
					b.observe(stats.UDPHealth, now)
					state := b.snapshot(now)
					input.circuit = &state
				}
				udp = append(udp, input)
			}
		}
		for i, network := range []string{"tcp", "udp"} {
			inputs, old := tcp, p.status.TCP
			if i == 1 {
				inputs, old = udp, p.status.UDP
			}
			d := evaluateSelector(config, inputs, old, now)
			if n, ok := p.nodes[d.NodeID]; d.NodeID != "" && (!ok || !n.Enabled) {
				d.NodeID, d.Reason = "", "selected_node_unavailable"
			}
			if old.NodeID != d.NodeID {
				p.status.Events = append(slices.Clone(p.status.Events), contract.SelectorEvent{At: now.UnixMilli(), Network: network, From: old.NodeID, To: d.NodeID, Reason: d.Reason})
				if len(p.status.Events) > 64 {
					p.status.Events = slices.Delete(p.status.Events, 0, len(p.status.Events)-64)
				}
				if old.NodeID != "" {
					p.status.Switches++
					mode := "manual"
					if config.Policy != nil {
						mode = config.Policy.Effective().Mode
					}
					s.runtime.metrics.switches.WithLabelValues(network, metricMode(mode), metricReason(d.Reason)).Inc()
				}
			} else if strings.Contains(d.Reason, "hysteresis") || d.Reason == "hold_or_cooldown" {
				p.status.Suppressed++
				mode := "manual"
				if config.Policy != nil {
					mode = config.Policy.Effective().Mode
				}
				s.runtime.metrics.suppressed.WithLabelValues(network, metricMode(mode), metricReason(d.Reason)).Inc()
			}
			weights, total := compileWeights(inputs, d.Candidates)
			if i == 0 {
				p.status.TCP, p.tcpWeights, p.tcpTotal = d, weights, total
				p.tcpOrder = compileSelectionOrder(config, inputs, d)
			} else {
				p.status.UDP, p.udpWeights, p.udpTotal = d, weights, total
				p.udpOrder = compileSelectionOrder(config, inputs, d)
			}
		}
		next.items[config.ID] = p
	}
	s.compileMetrics(next)
	s.snapshot.Store(next)
}

func (s *selectorRuntime) get(id string) (*preparedSelector, error) {
	snapshot := s.snapshot.Load()
	if snapshot != nil {
		if p := snapshot.items[id]; p != nil {
			return p, nil
		}
	}
	return nil, fmt.Errorf("%w: selector %s", plainstore.ErrNotFound, id)
}

func (s *selectorRuntime) target(ctx context.Context, network, id string) (netapi.Proxy, error) {
	p, err := s.get(id)
	if err != nil {
		return nil, err
	}
	if p.config.Policy != nil && p.config.Policy.Effective().Mode != "manual" {
		if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
			return nil, errors.New("invalid selector network")
		}
		netapi.GetContext(ctx).SetSelector(p.config.ID, p.config.Name)
		return &automaticSelectorProxy{runtime: s, id: id}, nil
	}
	return s.acquireTarget(ctx, network, id)
}
func (s *selectorRuntime) acquireTarget(ctx context.Context, network, id string) (netapi.Proxy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := s.get(id)
	if err != nil {
		return nil, err
	}
	d, weights, total, order := p.status.TCP, p.tcpWeights, p.tcpTotal, p.tcpOrder
	udp := strings.HasPrefix(network, "udp")
	if udp {
		d, weights, total, order = p.status.UDP, p.udpWeights, p.udpTotal, p.udpOrder
	} else if !strings.HasPrefix(network, "tcp") {
		return nil, errors.New("invalid selector network")
	}
	if total > 0 && p.config.Policy != nil && p.config.Policy.Mode == "weighted" && !p.config.Policy.Locked {
		d.NodeID = d.Candidates[pickWeighted(weights, rand.Uint64N(total))].NodeID
	}
	try := func(nodeID string) (netapi.Proxy, bool, error) {
		if nodeID == "" {
			return nil, false, nil
		}
		pair := p.circuits[nodeID]
		b := pair.tcp
		if udp {
			b = pair.udp
		}
		var permit *circuitPermit
		if b != nil {
			var ok bool
			permit, ok = b.tryAcquire(ctx, time.Now())
			if !ok {
				return nil, false, nil
			}
		}
		n := p.nodes[nodeID]
		netapi.GetContext(ctx).SetSelector(p.config.ID, p.config.Name)
		proxy, err := s.runtime.getContractDialer(ctx, n.ID, n, p.generations[n.ID])
		if err != nil {
			permit.finish()
			if b != nil {
				s.runtime.observer.counter(nodeID).constructionFailureAtGeneration(err, p.generations[nodeID])
			}
			return nil, true, err
		}
		if permit != nil {
			return &circuitPermitProxy{Proxy: proxy, permit: permit}, true, nil
		}
		return proxy, true, nil
	}
	if proxy, ok, err := try(d.NodeID); ok {
		return proxy, err
	}
	for _, nodeID := range order {
		if nodeID == d.NodeID {
			continue
		}
		if proxy, ok, err := try(nodeID); ok {
			return proxy, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("selector %q has no eligible %s candidate or recovery permit (%s)", p.config.Name, network, d.Reason)
}

func (r *NodeRuntime) refreshSelectors(ctx context.Context, nodes *plainstore.NodeStore) error {
	reloadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return r.selectors.reload(reloadCtx, nodes)
}

// SelectorService activates persisted changes without rebuilding routing rules.
// Existing TCP streams and UDP sessions retain their original outbound.
type SelectorService struct{ runtime *NodeRuntime }

func NewSelectorService(r *NodeRuntime) *SelectorService { return &SelectorService{r} }
func (s *SelectorService) store(ctx context.Context) (*plainstore.SelectorStore, *plainstore.NodeStore, error) {
	nodes, err := s.runtime.openNodes(ctx)
	if err != nil {
		return nil, nil, err
	}
	return s.runtime.selectors.store, nodes, nil
}
func (s *SelectorService) List(ctx context.Context) ([]contract.Selector, error) {
	store, _, err := s.store(ctx)
	if err != nil {
		return nil, err
	}
	return store.List(ctx)
}
func (s *SelectorService) Save(ctx context.Context, value contract.Selector) (contract.Selector, error) {
	store, nodes, err := s.store(ctx)
	if err != nil {
		return value, err
	}
	s.runtime.selectors.mu.Lock()
	effective := s.runtime.selectors.effectivePolicy(value)
	s.runtime.selectors.mu.Unlock()
	if effective.Policy != nil {
		if err := effective.Policy.Validate(); err != nil {
			return value, err
		}
	}
	value, err = store.Save(ctx, value)
	if err != nil {
		return value, err
	}
	err = s.runtime.refreshSelectors(ctx, nodes)
	return value, err
}
func (s *SelectorService) Delete(ctx context.Context, id string) error {
	store, nodes, err := s.store(ctx)
	if err != nil {
		return err
	}
	if err := store.Delete(ctx, id); err != nil {
		return err
	}
	return s.runtime.refreshSelectors(ctx, nodes)
}
func (s *SelectorService) References(ctx context.Context, id string) ([]contractroute.Reference, error) {
	store, _, err := s.store(ctx)
	if err != nil {
		return nil, err
	}
	return store.References(ctx, id)
}
func (s *SelectorService) Status(ctx context.Context, id string) (contract.SelectorRuntimeStatus, error) {
	if _, _, err := s.store(ctx); err != nil {
		return contract.SelectorRuntimeStatus{}, err
	}
	p, err := s.runtime.selectors.get(id)
	if err != nil {
		return contract.SelectorRuntimeStatus{}, err
	}
	status := p.status
	status.Events = slices.Clone(status.Events)
	status.TCP.Candidates = slices.Clone(status.TCP.Candidates)
	status.UDP.Candidates = slices.Clone(status.UDP.Candidates)
	for _, candidates := range [][]contract.SelectorCandidateStatus{status.TCP.Candidates, status.UDP.Candidates} {
		for i := range candidates {
			if c := candidates[i].Circuit; c != nil {
				candidates[i].Circuit = new(*c)
			}
			if c := candidates[i].Components; c != nil {
				candidates[i].Components = new(*c)
			}
		}
	}
	return status, nil
}

func (s *selectorRuntime) interfaceChanged(name string) {
	s.interfaceName.Store(new(name))
	select {
	case s.networkWake <- struct{}{}:
	default:
	}
}
func (s *selectorRuntime) reconcileInterface() {
	name := s.interfaceName.Load()
	if name == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.network.Generation++
	if s.platform != "android" {
		s.network.Online = *name != ""
	}
	s.scheduler.replace(nil, s.defaults.Probe.Concurrency)
	s.scheduleLocked()
}
