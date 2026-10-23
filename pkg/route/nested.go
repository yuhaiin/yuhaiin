package route

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

func recordMatch(store *netapi.Context, listName string, matched bool) {
	store.AddMatchHistory(listName, matched)
}

type Matcher interface {
	Match(context.Context, netapi.Address) bool
}

type Inbound struct {
	store *set.Set[string]
}

func NewInbound(inbounds ...string) *Inbound {
	i := &Inbound{
		store: set.NewSet[string](),
	}

	for _, v := range inbounds {
		if v != "" {
			i.store.Push(v)
		}
	}

	return i
}

func (s *Inbound) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)
	inbound := cmp.Or(store.GetInboundID(), store.GetInboundName())
	if inbound != "" {
		ok := s.store.Has(inbound)
		store.AddConditionHistory("inbound", inbound, cmp.Or(store.GetInboundName(), inbound), ok)
		return ok
	}

	store.AddConditionHistory("inbound", inbound, cmp.Or(store.GetInboundName(), inbound), false)
	return false
}

type Network struct {
	network string
}

func NewNetwork(network string) *Network {
	return &Network{
		network: network,
	}
}

func (s *Network) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)
	switch s.network {
	case "tcp", "network_tcp":
		ok := strings.HasPrefix(addr.Network(), "tcp")
		recordMatch(store, "Net TCP", ok)
		return ok
	case "udp", "network_udp":
		ok := strings.HasPrefix(addr.Network(), "udp")
		recordMatch(store, "Net UDP", ok)
		return ok
	default:
		return false
	}
}

type Port struct {
	set *set.Set[uint16]
}

func NewPort(ports string) *Port {
	p := &Port{
		set: set.NewSet[uint16](),
	}

	for part := range strings.SplitSeq(ports, ",") {
		start, end, isRange := strings.Cut(strings.TrimSpace(part), "-")
		first, err := strconv.ParseUint(start, 10, 16)
		if err != nil || first == 0 {
			continue
		}
		last := first
		if isRange {
			last, err = strconv.ParseUint(end, 10, 16)
			if err != nil || last < first {
				continue
			}
		}
		for port := first; port <= last; port++ {
			p.set.Push(uint16(port))
		}
	}

	return p
}

func (s *Port) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)
	port := uint16(addr.Port())
	ok := s.set.Has(port)
	if store.RecordingMatchHistory() {
		recordMatch(store, fmt.Sprintf("Port %d", port), ok)
	}
	return ok
}

type Geoip struct {
	countries *set.Set[string]
}

func NewGeoip(countries string) *Geoip {
	g := &Geoip{
		countries: set.NewSet[string](),
	}

	for v := range strings.SplitSeq(countries, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		g.countries.Push(v)
	}

	return g
}

func (s *Geoip) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)
	geo := store.GetGeo()
	ok := s.countries.Has(geo)
	recordMatch(store, fmt.Sprintf("Geoip %s", geo), ok)
	return ok
}

type And struct {
	matchers []Matcher
}

func NewAnd(matchers ...Matcher) *And {
	return &And{
		matchers: matchers,
	}
}

func (s *And) Match(ctx context.Context, addr netapi.Address) bool {
	for _, m := range s.matchers {
		if !m.Match(ctx, addr) {
			return false
		}
	}

	return true
}

type Or struct {
	name     string
	matchers []Matcher
}

func NewOr(name string, matchers ...Matcher) *Or {
	return &Or{
		name:     name,
		matchers: matchers,
	}
}

func (s *Or) Match(ctx context.Context, addr netapi.Address) bool {
	for _, m := range s.matchers {
		if m.Match(ctx, addr) {
			return true
		}
	}

	return false
}

type MatchEntry struct {
	id            string
	matcher       Matcher
	name          string
	mode          ModeEnum
	traceTemplate *contractconnection.MatchTraceTemplate
}

type Matchers struct {
	listNames      map[string]string
	listIssues     []contractroute.ListActivationIssue
	skippedRules   []contractroute.SkippedRouteRule
	degradedRules  []contractroute.DegradedRouteRule
	list           *Lists
	matchers       []MatchEntry
	mu             sync.RWMutex
	applyMu        sync.Mutex
	generation     uint64
	runtimeConfig  *RouteConfig
	prepareContext func(context.Context, *RouteConfig)
	hasGateway     atomic.Bool
}

func NewMatchers(list *Lists) *Matchers {
	return &Matchers{
		list: list,
	}
}

func (s *Matchers) appendRule(matchers []MatchEntry, r contractroute.RouteRule) []MatchEntry {
	if r.Disabled {
		return matchers
	}

	matcher := ParseMatcher(r)
	matchers = append(matchers, MatchEntry{
		id:            r.ID,
		mode:          modeEnumFromRule(r),
		matcher:       matcher,
		traceTemplate: buildMatchTraceTemplate(matcher),
		name:          r.Name,
	})

	return matchers
}

// appendPreparedRule retains branches that can still match deterministically.
// Unavailable lists are UNKNOWN, never FALSE: NOT UNKNOWN must remain UNKNOWN.
func (s *Matchers) appendPreparedRule(entries []MatchEntry, rule contractroute.RouteRule, unavailable, incomplete map[string]bool, skipped *[]contractroute.SkippedRouteRule, degraded *[]contractroute.DegradedRouteRule) []MatchEntry {
	if rule.Disabled {
		return entries
	}
	var missing []string
	_ = contractroute.VisitListRefs(rule.Rules, func(_ string, id string) error {
		if (unavailable[id] || incomplete[id]) && !slices.Contains(missing, id) {
			missing = append(missing, id)
		}
		return nil
	})
	if len(missing) == 0 {
		return s.appendRule(entries, rule)
	}
	slices.Sort(missing)
	matcher := parseMatcherWithUnavailable(rule, unavailable, incomplete)
	if canTrue, _ := possibleKnownMatch(matcher); !canTrue {
		*skipped = append(*skipped, contractroute.SkippedRouteRule{ID: rule.ID, Name: rule.Name, ListIDs: missing})
		return entries
	}
	*degraded = append(*degraded, contractroute.DegradedRouteRule{ID: rule.ID, Name: rule.Name, ListIDs: missing})
	return append(entries, MatchEntry{id: rule.ID, mode: modeEnumFromRule(rule), matcher: threeValuedMatcher{matcher}, traceTemplate: buildMatchTraceTemplate(matcher), name: rule.Name})
}

func (s *Matchers) Update(rules ...contractroute.RouteRule) error {
	return s.UpdateContext(context.Background(), rules...)
}

func (s *Matchers) UpdateContext(ctx context.Context, rules ...contractroute.RouteRule) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	prepared, err := s.list.prepareRules(ctx, rules)
	if err != nil {
		return err
	}
	var ms []MatchEntry
	var skipped []contractroute.SkippedRouteRule
	var degraded []contractroute.DegradedRouteRule
	for _, rule := range rules {
		ms = s.appendPreparedRule(ms, rule, prepared.unavailable, prepared.incomplete, &skipped, &degraded)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list.installPrepared(prepared)
	s.matchers = ms
	s.hasGateway.Store(slices.ContainsFunc(ms, func(entry MatchEntry) bool { return entry.mode.Mode() == ModeGateway }))
	s.listNames = prepared.names
	s.listIssues = prepared.listIssues
	s.skippedRules = skipped
	s.degradedRules = degraded
	s.generation++
	return nil
}

func (s *Matchers) UpdateSnapshot(ctx context.Context, snapshot plainstore.RouteSnapshot, activate func(context.Context, uint64, func()) error, config *RouteConfig, publish func()) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	prepared, err := s.list.prepareSnapshot(ctx, snapshot)
	if err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed && prepared != nil {
			prepared.close()
		}
	}()
	var entries []MatchEntry
	var skipped []contractroute.SkippedRouteRule
	var degraded []contractroute.DegradedRouteRule
	for _, entry := range snapshot.Rules {
		entries = s.appendPreparedRule(entries, entry.Rule, prepared.unavailable, prepared.incomplete, &skipped, &degraded)
	}
	return activate(ctx, snapshot.Revision, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.list.installPrepared(prepared)
		s.matchers = entries
		s.hasGateway.Store(slices.ContainsFunc(entries, func(entry MatchEntry) bool { return entry.mode.Mode() == ModeGateway }))
		s.listNames = prepared.names
		s.listIssues = prepared.listIssues
		s.skippedRules = skipped
		s.degradedRules = degraded
		s.runtimeConfig = config
		publish()
		s.generation++
		installed = true
	})
}

func (s *Matchers) Match(ctx context.Context, addr netapi.Address) ModeEnum {
	for {
		if ctx.Err() != nil {
			return ProxyMode
		}
		s.mu.RLock()
		generation, matchers, config := s.generation, s.matchers, s.runtimeConfig
		s.mu.RUnlock()
		if config != nil && s.prepareContext != nil {
			s.prepareContext(ctx, config)
		}
		state := netapi.GetContext(ctx)
		if geo := s.list.LoadGeoip(); geo != nil {
			state.SetGeo("")
			if country, err := geo.LookupAddr(ctx, addr); err == nil {
				state.SetGeo(country)
				metrics.Counter.AddGeoCountry(country)
			}
			state.ConnOptions().SetMaxminddb(geo)
		} else if state.ConnOptions().Maxminddb() != nil {
			state.SetGeo("")
			state.ConnOptions().SetMaxminddb(nil)
		}
		// Resolving an address may route a DNS connection recursively. Do not
		// hold the rule or index lock across resolver calls.
		hosts := s.list.SearchHost(ctx, addr)
		processes := s.list.ProcessTrie().Search(ctx, addr)
		s.mu.RLock()
		if generation != s.generation {
			s.mu.RUnlock()
			continue
		}
		store := netapi.GetContext(ctx)
		store.SetMatchedRule("", "")
		store.ConnOptions().SetMatchedLists(nil, s.listNames)
		store.ConnOptions().AddLists(hosts...).AddLists(processes...)
		for _, entry := range matchers {
			if entry.mode.Mode() == ModeGateway && (skipGateway(ctx) || addr.Network() != "tcp") {
				continue
			}
			store.NewRuleMatch(entry.id, entry.name)
			store.SetRuleMatchTemplate(entry.traceTemplate)
			if entry.matcher.Match(ctx, addr) {
				store.SetMatchedRule(entry.id, entry.name)
				s.mu.RUnlock()
				mode := entry.mode
				mode.config = config
				return mode
			}
		}
		s.mu.RUnlock()
		mode := ProxyMode
		if config != nil {
			mode = modeEnumFromRule(contractroute.RouteRule{Mode: config.DefaultMode, Target: config.DefaultTarget})
			if mode.mode.Unspecified() {
				mode.mode = ModeProxy
			}
			mode.config = config
		}
		return mode
	}
}

type List string

func (s List) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)

	if store.ConnOptions().HasList(string(s)) {
		store.AddConditionHistory("list", string(s), store.ConnOptions().ListName(string(s)), true)
		return true
	}

	store.AddConditionHistory("list", string(s), store.ConnOptions().ListName(string(s)), false)
	return false
}

func (s List) String() string {
	return string(s)
}

// ParseMatcher compiles boolean expressions only. List owns all matching
// data and index preparation; a List matcher only reads the match context.
func ParseMatcher(cc contractroute.RouteRule) Matcher {
	children := make([]Matcher, 0, len(cc.Rules))
	for _, expr := range cc.Rules {
		children = append(children, parseCondition(expr))
	}
	return NewOr(cc.Name, children...)
}

type constantMatcher bool

func (m constantMatcher) Match(context.Context, netapi.Address) bool { return bool(m) }

type notMatcher struct{ child Matcher }

func (m notMatcher) Match(ctx context.Context, addr netapi.Address) bool {
	return !m.child.Match(ctx, addr)
}

func parseCondition(expr contractroute.RuleExpr) Matcher {
	return parseConditionWithUnavailable(expr, nil)
}

func parseConditionWithUnavailable(expr contractroute.RuleExpr, unavailable map[string]bool) Matcher {
	return parseConditionWithDegraded(expr, unavailable, nil)
}

func parseConditionWithDegraded(expr contractroute.RuleExpr, unavailable, incomplete map[string]bool) Matcher {
	switch expr.Type {
	case "destination":
		if expr.Destination != nil {
			return newDestinationMatcher(*expr.Destination)
		}
	case "user", "group", "credential":
		value := expr.User
		if expr.Type == "group" {
			value = expr.Group
		}
		if expr.Type == "credential" {
			value = expr.Credential
		}
		if value != nil {
			return newIdentityMatcher(expr.Type, value.IDs)
		}
	case "always":
		return constantMatcher(true)
	case "all", "any":
		exprs := expr.All
		if expr.Type == "any" {
			exprs = expr.Any
		}
		if len(exprs) == 0 {
			return constantMatcher(false)
		}
		children := make([]Matcher, 0, len(exprs))
		for _, child := range sortRule(slices.Clone(exprs)) {
			children = append(children, parseConditionWithDegraded(child, unavailable, incomplete))
		}
		if expr.Type == "all" {
			return NewAnd(children...)
		}
		return NewOr("", children...)
	case "not":
		if expr.Not != nil {
			return notMatcher{parseConditionWithDegraded(*expr.Not, unavailable, incomplete)}
		}
	case "host":
		if expr.Host != nil {
			if unavailable[expr.Host.List] {
				return unavailableListMatcher(expr.Host.List)
			}
			if incomplete[expr.Host.List] {
				return incompleteListMatcher(expr.Host.List)
			}
			return List(expr.Host.List)
		}
	case "process":
		if expr.Process != nil {
			if unavailable[expr.Process.List] {
				return unavailableListMatcher(expr.Process.List)
			}
			if incomplete[expr.Process.List] {
				return incompleteListMatcher(expr.Process.List)
			}
			return List(expr.Process.List)
		}
	case "inbound":
		if expr.Inbound != nil {
			names := slices.Clone(expr.Inbound.Names)
			if expr.Inbound.Name != "" {
				names = append(names, expr.Inbound.Name)
			}
			return NewInbound(names...)
		}
	case "network":
		if expr.Network != nil {
			return NewNetwork(expr.Network.Network)
		}
	case "port":
		if expr.Port != nil {
			return NewPort(expr.Port.Ports)
		}
	case "geoip":
		if expr.GeoIP != nil {
			return NewGeoip(expr.GeoIP.Countries)
		}
	}
	return constantMatcher(false)
}

func sortRule(rules []contractroute.RuleExpr) []contractroute.RuleExpr {
	if len(rules) <= 1 {
		return rules
	}

	getNo := func(rule contractroute.RuleExpr) int {
		switch rule.Type {
		case "port", "network":
			return 1
		case "process":
			return 2
		case "inbound", "user", "group", "credential":
			return 3
		case "geoip":
			return 4
		case "host":
			return 5
		default:
			return math.MaxInt
		}
	}

	slices.SortFunc(rules,
		func(a, b contractroute.RuleExpr) int { return cmp.Compare(getNo(a), getNo(b)) })

	return rules
}
