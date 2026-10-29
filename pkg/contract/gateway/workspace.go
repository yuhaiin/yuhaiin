package gateway

import (
	"errors"
	"fmt"
	"slices"
)

// Workspace is the Gateway-first editable view of Config. A policy, backend pool
// or filter has exactly one owner; ownership is a structural property, not a
// second mutable relation in the UI. Runtime compilation still uses Config.
type Workspace struct {
	Version  int                `json:"version"`
	Revision uint64             `json:"revision"`
	Gateways []WorkspaceGateway `json:"gateways"`
}

type WorkspaceGateway struct {
	ID                 string                `json:"id"`
	Name               string                `json:"name"`
	Enabled            bool                  `json:"enabled"`
	RejectWhenDisabled bool                  `json:"rejectWhenDisabled,omitzero"`
	Debug              bool                  `json:"debug"`
	Revision           uint64                `json:"revision"`
	Listener           *ListenerSource       `json:"listener,omitempty"`
	Policies           []Rule                `json:"policies"`
	BackendPools       []Upstream            `json:"backendPools"`
	Interception       *InterceptionSettings `json:"interception,omitempty"`
	Filters            []FilterList          `json:"filters"`
	Fallback           Action                `json:"fallback"`
	MaxBodyBytes       int64                 `json:"maxBodyBytes"`
}

type ListenerSource struct {
	Listen                string   `json:"listen"`
	AllowedSources        []string `json:"allowedSources"`
	TLSMode               string   `json:"tlsMode"`
	CertificateFile       string   `json:"certificateFile,omitempty"`
	KeyFile               string   `json:"keyFile,omitempty"`
	ManagedCertificateIDs []string `json:"managedCertificateIds,omitempty"`
	ACMEHTTP01            bool     `json:"acmeHttp01,omitzero"`
}

// PreserveDisabledGuards prevents an older editor from removing an import
// safety guard. Explicitly enabling the Gateway releases the guard.
func PreserveDisabledGuards(old, next []Gateway) []Gateway {
	guarded := make(map[string]bool, len(old))
	for _, g := range old {
		guarded[g.ID] = g.RejectWhenDisabled
	}
	result := slices.Clone(next)
	for i := range result {
		g := &result[i]
		if g.Enabled {
			g.RejectWhenDisabled = false
		} else if guarded[g.ID] {
			g.RejectWhenDisabled = true
		}
	}
	return result
}

// InterceptionSettings controls HTTP/TLS handling after Routing selects the
// owning Gateway. Routing owns Inbound selection.
type InterceptionSettings struct {
	Mode           string   `json:"mode"`
	Domains        []string `json:"domains"`
	ExcludeDomains []string `json:"excludeDomains"`
	Ports          []uint16 `json:"ports"`
	Sources        []string `json:"sources"`
	Processes      []string `json:"processes"`
	UnknownTLS     string   `json:"unknownTls"`
}

// NormalizeCondition converts legacy single-value leaves to the canonical
// multi-value representation. The result owns its child slices and never
// exposes deprecated "value" in a newly serialized configuration.
func NormalizeCondition(c Condition) Condition {
	if c.Field != "" {
		if len(c.Values) == 0 && c.Value != "" {
			c.Values = []string{c.Value}
		}
		c.Value = ""
		return c
	}
	if c.All != nil {
		children := make([]Condition, len(c.All))
		for i, child := range c.All {
			children[i] = NormalizeCondition(child)
		}
		c.All = children
	}
	if c.Any != nil {
		children := make([]Condition, len(c.Any))
		for i, child := range c.Any {
			children[i] = NormalizeCondition(child)
		}
		c.Any = children
	}
	if c.Not != nil {
		child := NormalizeCondition(*c.Not)
		c.Not = &child
	}
	c.Value = ""
	return c
}

func settingsOf(i Interception) InterceptionSettings {
	return InterceptionSettings{
		Mode:    i.Mode,
		Domains: i.Domains, ExcludeDomains: i.ExcludeDomains,
		Ports: i.Ports, Sources: i.Sources,
		Processes: i.Processes, UnknownTLS: i.UnknownTLS,
	}
}

func (s InterceptionSettings) interception(gatewayID string) Interception {
	return Interception{
		GatewayID: gatewayID, Mode: s.Mode,
		Domains: s.Domains, ExcludeDomains: s.ExcludeDomains,
		Ports: s.Ports, Sources: s.Sources,
		Processes: s.Processes, UnknownTLS: s.UnknownTLS,
	}
}

// WorkspaceFromConfig is deliberately strict. Sharing a mutable rule or pool
// between Gateways or storing orphaned resources is not part of the v2 model.
// Do not silently drop such resources when projecting a persisted snapshot.
func WorkspaceFromConfig(cfg Config) (Workspace, error) {
	doc := Workspace{Version: 2, Revision: cfg.Revision, Gateways: make([]WorkspaceGateway, 0, len(cfg.Gateways))}
	rules := make(map[string]Rule, len(cfg.Rules))
	pools := make(map[string]Upstream, len(cfg.Upstreams))
	seenRules := make(map[string]string)
	seenPools := make(map[string]string)
	seenInterceptions := make(map[string]bool)
	seenFilters := make(map[string]bool)

	for _, rule := range cfg.Rules {
		if rule.ID == "" {
			return Workspace{}, errors.New("workspace rule has empty ID")
		}
		if _, exists := rules[rule.ID]; exists {
			return Workspace{}, fmt.Errorf("duplicate workspace rule %s", rule.ID)
		}
		rule.Match = NormalizeCondition(rule.Match)
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
			ID: g.ID, Name: g.Name, Enabled: g.Enabled, RejectWhenDisabled: g.RejectWhenDisabled, Revision: g.Revision,
			Debug: g.Debug, MaxBodyBytes: g.MaxBodyBytes, Fallback: g.Default,
			Policies: []Rule{}, BackendPools: []Upstream{},
			Filters: []FilterList{},
		}
		if g.Listen != "" {
			entry.Listener = &ListenerSource{
				Listen: g.Listen, AllowedSources: g.AllowedSources, TLSMode: g.TLSMode,
				CertificateFile: g.CertificateFile, KeyFile: g.KeyFile,
				ManagedCertificateIDs: g.ManagedCertificateIDs, ACMEHTTP01: g.ACMEHTTP01,
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
			if seenInterceptions[intercept.GatewayID] {
				return Workspace{}, fmt.Errorf("duplicate Gateway interception %s", intercept.GatewayID)
			}
			seenInterceptions[intercept.GatewayID] = true
			settings := settingsOf(intercept)
			entry.Interception = &settings
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
	if len(seenInterceptions) != len(cfg.Interceptions) {
		return Workspace{}, errors.New("workspace contains orphan Gateway interceptions")
	}
	if len(seenFilters) != len(cfg.FilterLists) {
		return Workspace{}, errors.New("workspace contains orphan filters")
	}
	return doc, nil
}

// ConfigFromWorkspace projects a single nested revision into the existing
// compiler representation. It never reads or mutates a previously saved Config.
func ConfigFromWorkspace(doc Workspace) (Config, error) {
	if doc.Version != 2 {
		return Config{}, fmt.Errorf("unsupported Gateway workspace version %d (expected 2)", doc.Version)
	}
	cfg := Config{
		Revision: doc.Revision, Gateways: []Gateway{}, Rules: []Rule{},
		Upstreams: []Upstream{}, Interceptions: []Interception{},
		FilterLists: []FilterList{},
	}
	seenGateway := map[string]bool{}
	seenRule := map[string]bool{}
	seenPool := map[string]bool{}
	seenFilter := map[string]bool{}
	for _, g := range doc.Gateways {
		if g.ID == "" || seenGateway[g.ID] {
			return Config{}, fmt.Errorf("duplicate or empty Gateway ID %q", g.ID)
		}
		seenGateway[g.ID] = true
		entry := Gateway{ID: g.ID, Name: g.Name, Enabled: g.Enabled, RejectWhenDisabled: g.RejectWhenDisabled, Revision: g.Revision,
			Debug: g.Debug, MaxBodyBytes: g.MaxBodyBytes, Default: g.Fallback, RuleIDs: []string{}}
		if g.Listener != nil {
			entry.Listen, entry.AllowedSources = g.Listener.Listen, g.Listener.AllowedSources
			entry.TLSMode, entry.CertificateFile, entry.KeyFile =
				g.Listener.TLSMode, g.Listener.CertificateFile, g.Listener.KeyFile
			entry.ManagedCertificateIDs, entry.ACMEHTTP01 = g.Listener.ManagedCertificateIDs, g.Listener.ACMEHTTP01
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
			rule.Match = NormalizeCondition(rule.Match)
			cfg.Rules = append(cfg.Rules, rule)
		}
		if g.Interception != nil {
			cfg.Interceptions = append(cfg.Interceptions, g.Interception.interception(g.ID))
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
