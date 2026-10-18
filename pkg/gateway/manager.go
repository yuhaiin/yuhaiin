package gateway

import (
	"context"
	"crypto/tls"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type ConfigStore interface {
	Load(context.Context) (contract.Config, error)
	Save(context.Context, contract.Config) (contract.Config, error)
}

type gatewayRuntime struct {
	engine  *Engine
	tls     *tls.Config
	sources []netip.Prefix
}
type snapshot struct {
	config        contract.Config
	gateways      map[string]*gatewayRuntime
	listeners     map[string]*gatewayRuntime
	interceptions []interceptRule
}

func (s *snapshot) close() {
	for _, g := range s.gateways {
		_ = g.engine.Close()
	}
}

// Manager serializes management changes, stages all listeners/policies, commits
// SQLite, then publishes one immutable snapshot. No fallible work follows commit.
type Manager struct {
	mu                  sync.Mutex
	store               ConfigStore
	selectOutbound      SelectOutbound
	current             atomic.Pointer[snapshot]
	listeners           map[string]*listenerRuntime
	Authority           *Authority
	closed              bool
	recoverDestination  func(context.Context, netapi.Address) netapi.Address
	lookupProcess       func(context.Context, netapi.Address)
	internalConnections sync.Map
	sessionsMu          sync.Mutex
	sessions            map[net.Conn]interceptSession
}

type Option func(*Manager)

func WithDestinationRecovery(f func(context.Context, netapi.Address) netapi.Address) Option {
	return func(m *Manager) { m.recoverDestination = f }
}
func WithProcessLookup(f func(context.Context, netapi.Address)) Option {
	return func(m *Manager) { m.lookupProcess = f }
}

func NewManager(ctx context.Context, store ConfigStore, authority *Authority, selectOutbound SelectOutbound, options ...Option) (*Manager, error) {
	m := &Manager{store: store, Authority: authority, selectOutbound: selectOutbound, listeners: make(map[string]*listenerRuntime), sessions: make(map[net.Conn]interceptSession)}
	for _, option := range options {
		option(m)
	}
	config, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	prepared, err := m.prepare(config)
	if err != nil {
		return nil, err
	}
	listeners, err := m.stageListeners(prepared)
	if err != nil {
		prepared.close()
		return nil, err
	}
	m.current.Store(prepared)
	m.publishListeners(listeners, prepared)
	return m, nil
}

func (m *Manager) Config() contract.Config {
	// Never return aliases into a snapshot to an API decoder or editor.
	data, _ := json.Marshal(m.current.Load().config)
	var config contract.Config
	_ = json.Unmarshal(data, &config)
	return config
}

func (m *Manager) Save(ctx context.Context, config contract.Config) (contract.Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return config, net.ErrClosed
	}
	var err error
	config, err = reviseConfig(m.current.Load().config, config)
	if err != nil {
		return config, err
	}
	prepared, err := m.prepare(config)
	if err != nil {
		return config, err
	}
	listeners, err := m.stageListeners(prepared)
	if err != nil {
		prepared.close()
		return config, err
	}
	saved, err := m.store.Save(ctx, prepared.config)
	if err != nil {
		for _, l := range listeners {
			_ = l.server.Close()
			_ = l.raw.Close()
		}
		prepared.close()
		return config, err
	}
	prepared.config = saved
	old := m.current.Swap(prepared)
	m.publishListeners(listeners, prepared)
	old.close()
	return m.Config(), nil
}

func (m *Manager) prepare(config contract.Config) (*snapshot, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	if len(data) > 8<<20 {
		return nil, errors.New("gateway configuration exceeds 8 MiB")
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	s := &snapshot{config: config, gateways: make(map[string]*gatewayRuntime), listeners: make(map[string]*gatewayRuntime)}
	success := false
	defer func() {
		if !success {
			s.close()
		}
	}()
	rules := make(map[string]contract.Rule)
	for _, r := range config.Rules {
		if r.ID == "" || rules[r.ID].ID != "" {
			return nil, errors.New("duplicate or empty rule ID")
		}
		rules[r.ID] = r
	}
	// Compile unused/disabled rules and upstreams too, so invalid drafts cannot
	// become active later through an unrelated enable operation.
	if _, err := CompilePolicy(config.Rules, contract.Action{Type: "block"}); err != nil {
		return nil, err
	}
	upstreamIDs := make(map[string]bool)
	for _, u := range config.Upstreams {
		if upstreamIDs[u.ID] {
			return nil, errors.New("duplicate upstream ID")
		}
		if _, err := compileUpstream(u); err != nil {
			return nil, err
		}
		upstreamIDs[u.ID] = true
	}
	for _, r := range config.Rules {
		if r.Action.Type == "reverse_proxy" && !upstreamIDs[r.Action.Upstream] {
			return nil, fmt.Errorf("rule %s references missing upstream", r.ID)
		}
	}
	for _, g := range config.Gateways {
		if g.ID == "" || g.Name == "" || s.gateways[g.ID] != nil || g.MaxBodyBytes < 0 {
			return nil, errors.New("gateway requires unique ID, name and valid body limit")
		}
		if !slices.Contains([]string{"", "off", "termination"}, g.TLSMode) {
			return nil, errors.New("listener TLS mode must be off or termination")
		}
		selected := make([]contract.Rule, 0, len(g.RuleIDs))
		seen := make(map[string]bool)
		for _, id := range g.RuleIDs {
			rule, ok := rules[id]
			if !ok || seen[id] {
				return nil, fmt.Errorf("gateway %s has missing or duplicate rule %s", g.ID, id)
			}
			seen[id] = true
			selected = append(selected, rule)
		}
		engine, err := NewEngine(g, selected, config.Upstreams, m.selectForRequest)
		if err != nil {
			return nil, fmt.Errorf("gateway %s: %w", g.ID, err)
		}
		entry := &gatewayRuntime{engine: engine}
		if previous := m.current.Load(); previous != nil {
			if old := previous.gateways[g.ID]; old != nil {
				engine.Counters = old.engine.Counters
			}
		}
		s.gateways[g.ID] = entry
		for _, source := range g.AllowedSources {
			prefix, err := netip.ParsePrefix(source)
			if err != nil {
				return nil, fmt.Errorf("invalid source CIDR %q", source)
			}
			entry.sources = append(entry.sources, prefix)
		}
		if g.TLSMode == "termination" {
			certificate, err := tls.LoadX509KeyPair(g.CertificateFile, g.KeyFile)
			if err != nil {
				return nil, errors.New("load gateway listener certificate failed")
			}
			entry.tls = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}}
		}
		if g.Listen != "" {
			host, _, err := net.SplitHostPort(g.Listen)
			if err != nil {
				return nil, err
			}
			ip, err := netip.ParseAddr(host)
			if (err != nil || !ip.IsLoopback()) && len(entry.sources) == 0 {
				return nil, errors.New("non-loopback gateway listener requires allowedSources CIDRs")
			}
			if _, exists := s.listeners[g.Listen]; exists {
				return nil, errors.New("duplicate gateway listen address")
			}
			// Reserve disabled addresses too to reject ambiguous configurations.
			s.listeners[g.Listen] = entry
		}
	}
	seenInbounds := make(map[string]bool)
	for _, i := range config.Interceptions {
		g := s.gateways[i.GatewayID]
		if g == nil || i.InboundID == "" {
			return nil, errors.New("interception requires existing gateway and inbound")
		}
		if !slices.Contains([]string{"off", "http_only", "tls_passthrough", "https_mitm"}, i.Mode) {
			return nil, errors.New("unsupported interception mode")
		}
		if i.Mode == "https_mitm" && (m.Authority == nil || !m.Authority.Status().Present) {
			return nil, errors.New("generate a gateway CA before enabling MITM")
		}
		if seenInbounds[i.InboundID] {
			return nil, errors.New("only one interception setting is allowed per inbound")
		}
		seenInbounds[i.InboundID] = true
		if i.Mode == "https_mitm" && len(i.Domains) == 0 {
			return nil, errors.New("MITM requires an explicit domain allowlist")
		}
		if !slices.Contains([]string{"", "passthrough", "reject"}, i.UnknownTLS) {
			return nil, errors.New("unknown TLS strategy must be passthrough or reject")
		}
		entry := interceptRule{config: i}
		for _, source := range i.Sources {
			prefix, err := netip.ParsePrefix(source)
			if err != nil {
				return nil, err
			}
			entry.sources = append(entry.sources, prefix)
		}
		for _, domain := range append(slices.Clone(i.Domains), i.ExcludeDomains...) {
			if hostname(strings.TrimPrefix(domain, "*.")) == "" || strings.ContainsAny(strings.TrimPrefix(domain, "*."), "/ *\r\n") {
				return nil, errors.New("invalid interception domain")
			}
		}
		if i.Mode != "off" {
			s.interceptions = append(s.interceptions, entry)
		}
	}
	for _, list := range config.FilterLists {
		if s.gateways[list.GatewayID] == nil {
			return nil, errors.New("filter list references missing gateway")
		}
	}
	for id, g := range s.gateways {
		var lists []contract.FilterList
		for _, list := range config.FilterLists {
			if list.GatewayID == id {
				lists = append(lists, list)
			}
		}
		filters, err := CompileFilters(lists)
		if err != nil {
			return nil, err
		}
		g.engine.filters = filters
	}
	for _, g := range s.gateways {
		if !g.engine.config.Enabled && g.engine.config.Listen != "" {
			delete(s.listeners, g.engine.config.Listen)
		}
	}
	success = true
	return s, nil
}

func (m *Manager) Test(request contract.TestRequest) (contract.TestResult, error) {
	s := m.current.Load()
	g := s.gateways[request.GatewayID]
	if g == nil {
		return contract.TestResult{}, errors.New("gateway not found")
	}
	return g.engine.Test(request)
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	m.sessionsMu.Lock()
	for conn := range m.sessions {
		_ = conn.Close()
	}
	m.sessionsMu.Unlock()
	for addr, l := range m.listeners {
		_ = l.server.Close()
		_ = l.raw.Close()
		delete(m.listeners, addr)
	}
	if s := m.current.Load(); s != nil {
		s.close()
	}
	return nil
}
