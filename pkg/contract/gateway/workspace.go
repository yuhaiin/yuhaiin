package gateway

import (
	"errors"
	"fmt"
)

// Workspace is the Gateway-first editable view of Config. A policy, backend pool
// or filter has exactly one owner; ownership is a structural property, not a
// second mutable relation in the UI. Runtime compilation still uses Config.
type Workspace struct {
	Revision uint64             `json:"revision"`
	Gateways []WorkspaceGateway `json:"gateways"`
}

type WorkspaceGateway struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Enabled      bool            `json:"enabled"`
	Revision     uint64          `json:"revision"`
	Listener     *ListenerSource `json:"listener,omitempty"`
	Policies     []Rule          `json:"policies"`
	BackendPools []Upstream      `json:"backendPools"`
	Sources      []InboundSource `json:"sources"`
	Filters      []FilterList    `json:"filters"`
	Fallback     Action          `json:"fallback"`
	MaxBodyBytes int64           `json:"maxBodyBytes"`
}

type ListenerSource struct {
	Listen          string   `json:"listen"`
	AllowedSources  []string `json:"allowedSources"`
	TLSMode         string   `json:"tlsMode"`
	CertificateFile string   `json:"certificateFile,omitempty"`
	KeyFile         string   `json:"keyFile,omitempty"`
}

type InboundSource struct {
	InboundID      string   `json:"inboundId"`
	Mode           string   `json:"mode"`
	Domains        []string `json:"domains"`
	ExcludeDomains []string `json:"excludeDomains"`
	Ports          []uint16 `json:"ports"`
	Sources        []string `json:"sources"`
	Processes      []string `json:"processes"`
	UnknownTLS     string   `json:"unknownTls"`
}

func sourceOf(i Interception) InboundSource {
	return InboundSource{
		InboundID: i.InboundID, Mode: i.Mode,
		Domains: i.Domains, ExcludeDomains: i.ExcludeDomains,
		Ports: i.Ports, Sources: i.Sources,
		Processes: i.Processes, UnknownTLS: i.UnknownTLS,
	}
}

func (s InboundSource) interception(gatewayID string) Interception {
	return Interception{
		InboundID: s.InboundID, GatewayID: gatewayID, Mode: s.Mode,
		Domains: s.Domains, ExcludeDomains: s.ExcludeDomains,
		Ports: s.Ports, Sources: s.Sources,
		Processes: s.Processes, UnknownTLS: s.UnknownTLS,
	}
}

// WorkspaceFromConfig is deliberately strict. Sharing a mutable rule or pool
// between Gateways or storing orphaned resources is not part of the v2 model.
// Do not silently drop such resources when projecting a persisted snapshot.
func WorkspaceFromConfig(cfg Config) (Workspace, error) {
	doc := Workspace{Revision: cfg.Revision, Gateways: make([]WorkspaceGateway, 0, len(cfg.Gateways))}
	rules := make(map[string]Rule, len(cfg.Rules))
	pools := make(map[string]Upstream, len(cfg.Upstreams))
	seenRules := make(map[string]string)
	seenPools := make(map[string]string)
	seenInbounds := make(map[string]bool)
	seenFilters := make(map[string]bool)

	for _, rule := range cfg.Rules {
		if rule.ID == "" {
			return Workspace{}, errors.New("workspace rule has empty ID")
		}
		if _, exists := rules[rule.ID]; exists {
			return Workspace{}, fmt.Errorf("duplicate workspace rule %s", rule.ID)
		}
		rules[rule.ID] = rule
	}
	for _, pool := range cfg.Upstreams {
		if pool.ID == "" {
			return Workspace{}, errors.New("workspace pool has empty ID")
		}
		if _, exists := pools[pool.ID]; exists {
			return Workspace{}, fmt.Errorf("duplicate workspace pool %s", pool.ID)
		}
		pools[pool.ID] = pool
	}

	for _, g := range cfg.Gateways {
		entry := WorkspaceGateway{
			ID: g.ID, Name: g.Name, Enabled: g.Enabled, Revision: g.Revision,
			MaxBodyBytes: g.MaxBodyBytes, Fallback: g.Default,
			Policies: []Rule{}, BackendPools: []Upstream{},
			Sources: []InboundSource{}, Filters: []FilterList{},
		}
		if g.Listen != "" {
			entry.Listener = &ListenerSource{
				Listen: g.Listen, AllowedSources: g.AllowedSources, TLSMode: g.TLSMode,
				CertificateFile: g.CertificateFile, KeyFile: g.KeyFile,
			}
		}
		usedPools := make(map[string]bool)
		assignPool := func(a Action) error {
			if a.Type != "reverse_proxy" {
				return nil
			}
			pool, ok := pools[a.Upstream]
			if !ok {
				return fmt.Errorf("gateway %s references missing backend pool %q", g.ID, a.Upstream)
			}
			if owner, exists := seenPools[pool.ID]; exists && owner != g.ID {
				return fmt.Errorf("backend pool %s is shared by %s and %s", pool.ID, owner, g.ID)
			}
			seenPools[pool.ID] = g.ID
			if !usedPools[pool.ID] {
				usedPools[pool.ID] = true
				entry.BackendPools = append(entry.BackendPools, pool)
			}
			return nil
		}
		if err := assignPool(g.Default); err != nil {
			return Workspace{}, err
		}
		for _, id := range g.RuleIDs {
			rule, ok := rules[id]
			if !ok {
				return Workspace{}, fmt.Errorf("gateway %s references missing policy %s", g.ID, id)
			}
			if owner, exists := seenRules[id]; exists {
				return Workspace{}, fmt.Errorf("policy %s belongs to multiple Gateways (%s and %s)", id, owner, g.ID)
			}
			seenRules[id] = g.ID
			entry.Policies = append(entry.Policies, rule)
			if err := assignPool(rule.Action); err != nil {
				return Workspace{}, err
			}
		}
		for _, intercept := range cfg.Interceptions {
			if intercept.GatewayID != g.ID {
				continue
			}
			if seenInbounds[intercept.InboundID] {
				return Workspace{}, fmt.Errorf("duplicate inbound source %s", intercept.InboundID)
			}
			seenInbounds[intercept.InboundID] = true
			entry.Sources = append(entry.Sources, sourceOf(intercept))
		}
		for _, filter := range cfg.FilterLists {
			if filter.GatewayID != g.ID {
				continue
			}
			if seenFilters[filter.ID] {
				return Workspace{}, fmt.Errorf("duplicate filter %s", filter.ID)
			}
			seenFilters[filter.ID] = true
			entry.Filters = append(entry.Filters, filter)
		}
		doc.Gateways = append(doc.Gateways, entry)
	}
	for id := range rules {
		if _, ok := seenRules[id]; !ok {
			return Workspace{}, fmt.Errorf("orphan HTTP policy %s", id)
		}
	}
	for id := range pools {
		if _, ok := seenPools[id]; !ok {
			return Workspace{}, fmt.Errorf("orphan backend pool %s", id)
		}
	}
	if len(seenInbounds) != len(cfg.Interceptions) {
		return Workspace{}, errors.New("workspace contains orphan inbound sources")
	}
	if len(seenFilters) != len(cfg.FilterLists) {
		return Workspace{}, errors.New("workspace contains orphan filters")
	}
	return doc, nil
}

// ConfigFromWorkspace projects a single nested revision into the existing
// compiler representation. It never reads or mutates a previously saved Config.
func ConfigFromWorkspace(doc Workspace) (Config, error) {
	cfg := Config{
		Revision: doc.Revision, Gateways: []Gateway{}, Rules: []Rule{},
		Upstreams: []Upstream{}, Interceptions: []Interception{},
		FilterLists: []FilterList{},
	}
	seenGateway := map[string]bool{}
	seenRule := map[string]bool{}
	seenPool := map[string]bool{}
	seenSource := map[string]bool{}
	seenFilter := map[string]bool{}
	for _, g := range doc.Gateways {
		if g.ID == "" || seenGateway[g.ID] {
			return Config{}, fmt.Errorf("duplicate or empty Gateway ID %q", g.ID)
		}
		seenGateway[g.ID] = true
		entry := Gateway{ID: g.ID, Name: g.Name, Enabled: g.Enabled, Revision: g.Revision,
			MaxBodyBytes: g.MaxBodyBytes, Default: g.Fallback, RuleIDs: []string{}}
		if g.Listener != nil {
			entry.Listen, entry.AllowedSources = g.Listener.Listen, g.Listener.AllowedSources
			entry.TLSMode, entry.CertificateFile, entry.KeyFile =
				g.Listener.TLSMode, g.Listener.CertificateFile, g.Listener.KeyFile
		}
		pools := map[string]bool{}
		for _, pool := range g.BackendPools {
			if pool.ID == "" || seenPool[pool.ID] {
				return Config{}, fmt.Errorf("duplicate or empty backend pool %q", pool.ID)
			}
			seenPool[pool.ID] = true
			pools[pool.ID] = true
			cfg.Upstreams = append(cfg.Upstreams, pool)
		}
		checkAction := func(a Action) error {
			if a.Type == "reverse_proxy" && !pools[a.Upstream] {
				return fmt.Errorf("gateway %s references foreign backend pool %q", g.ID, a.Upstream)
			}
			return nil
		}
		if err := checkAction(g.Fallback); err != nil {
			return Config{}, err
		}
		for _, rule := range g.Policies {
			if rule.ID == "" || seenRule[rule.ID] {
				return Config{}, fmt.Errorf("duplicate or empty HTTP policy %q", rule.ID)
			}
			if err := checkAction(rule.Action); err != nil {
				return Config{}, err
			}
			seenRule[rule.ID] = true
			entry.RuleIDs = append(entry.RuleIDs, rule.ID)
			cfg.Rules = append(cfg.Rules, rule)
		}
		for _, src := range g.Sources {
			if src.InboundID == "" || seenSource[src.InboundID] {
				return Config{}, fmt.Errorf("duplicate or empty inbound source %q", src.InboundID)
			}
			seenSource[src.InboundID] = true
			cfg.Interceptions = append(cfg.Interceptions, src.interception(g.ID))
		}
		for _, filter := range g.Filters {
			if filter.ID == "" || seenFilter[filter.ID] {
				return Config{}, fmt.Errorf("duplicate or empty URL filter %q", filter.ID)
			}
			seenFilter[filter.ID] = true
			filter.GatewayID = g.ID
			cfg.FilterLists = append(cfg.FilterLists, filter)
		}
		cfg.Gateways = append(cfg.Gateways, entry)
	}
	return cfg, nil
}
