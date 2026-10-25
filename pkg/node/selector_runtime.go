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
	config                 contract.Selector
	nodes                  map[string]contract.Node
	status                 contract.SelectorRuntimeStatus
	tcpWeights, udpWeights []weightedChoice
	tcpTotal, udpTotal     uint64
}

type selectorSnapshot struct{ items map[string]*preparedSelector }

// selectorRuntime has one worker per core instance. Connection creation reads
// immutable snapshots, with neither database access nor ranking on the hot path.
type selectorRuntime struct {
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
	s := &selectorRuntime{networkWake: make(chan struct{}, 1), scheduler: newProbeScheduler(), monitorStore: plainstore.NewMonitoringStore(r.sqlite.DB()), network: defaultMonitoringNetwork(), platform: runtime.GOOS, runtime: r, store: plainstore.NewSelectorStore(r.sqlite.DB()), stop: make(chan struct{}), done: make(chan struct{})}
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
	s.configs, s.nodes, s.counters = configs, byID, counters
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
	next := &selectorSnapshot{items: make(map[string]*preparedSelector, len(s.configs))}
	for _, config := range s.configs {
		config = s.effectivePolicy(config)
		p := &preparedSelector{config: config, nodes: make(map[string]contract.Node), status: contract.SelectorRuntimeStatus{ID: config.ID, Revision: config.Revision, Events: []contract.SelectorEvent{}}}
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
				input := selectionInput{config: c, enabled: exists && n.Enabled, health: stats.TCPHealth, speed: stats.Throughput, active: counter.activeTCP.Load() + counter.activeUDP.Load()}
				tcp = append(tcp, input)
				input.health = stats.UDPHealth
				input.udp = true
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
				}
			} else if strings.Contains(d.Reason, "hysteresis") || d.Reason == "hold_or_cooldown" {
				p.status.Suppressed++
			}
			weights, total := compileWeights(inputs, d.Candidates)
			if i == 0 {
				p.status.TCP, p.tcpWeights, p.tcpTotal = d, weights, total
			} else {
				p.status.UDP, p.udpWeights, p.udpTotal = d, weights, total
			}
		}
		next.items[config.ID] = p
	}
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
	d, weights, total := p.status.TCP, p.tcpWeights, p.tcpTotal
	if strings.HasPrefix(network, "udp") {
		d, weights, total = p.status.UDP, p.udpWeights, p.udpTotal
	} else if !strings.HasPrefix(network, "tcp") {
		return nil, errors.New("invalid selector network")
	}
	if total > 0 && p.config.Policy != nil && p.config.Policy.Mode == "weighted" && !p.config.Policy.Locked {
		d.NodeID = d.Candidates[pickWeighted(weights, rand.Uint64N(total))].NodeID
	}
	if d.NodeID == "" {
		return nil, fmt.Errorf("selector %q has no eligible %s candidate (%s)", p.config.Name, network, d.Reason)
	}
	n := p.nodes[d.NodeID]
	netapi.GetContext(ctx).SetSelector(p.config.ID, p.config.Name)
	return s.runtime.getContractDialer(ctx, n.ID, n)
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
