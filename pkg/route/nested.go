package route

import (
	"cmp"
	"context"
	"fmt"
	"iter"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

func shouldRecordMatchHistory() bool {
	return configuration.ExtendedStatsEnabled.Load()
}

func startMatch(store *netapi.Context, ruleName string) {
	if !shouldRecordMatchHistory() {
		return
	}

	store.NewMatch(ruleName)
}

func recordMatch(store *netapi.Context, listName string, matched bool) {
	if !shouldRecordMatchHistory() {
		return
	}

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
	inbound := store.GetInboundName()
	if inbound != "" {
		ok := s.store.Has(inbound)
		recordMatch(store, inbound, ok)
		return ok
	}

	recordMatch(store, inbound, false)
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

	for v := range strings.SplitSeq(ports, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		port, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			continue
		}
		p.set.Push(uint16(port))
	}

	return p
}

func (s *Port) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)
	port := uint16(addr.Port())
	ok := s.set.Has(port)
	recordMatch(store, fmt.Sprintf("Port %d", port), ok)
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
	matcher Matcher
	name    string
	mode    ModeEnum
}

type Matchers struct {
	list     *Lists
	tags     *set.Set[string]
	matchers []MatchEntry
	mu       sync.RWMutex
}

func NewMatchers(list *Lists) *Matchers {
	return &Matchers{
		list: list,
		tags: set.NewSet[string](),
	}
}

func (s *Matchers) appendRule(matchers []MatchEntry, r contractroute.RouteRule) []MatchEntry {
	if r.Disabled {
		return matchers
	}

	matchers = append(matchers, MatchEntry{
		mode:    modeEnumFromRule(r),
		matcher: ParseMatcher(s.list, r),
		name:    r.Name,
	})

	if tag := r.Tag; tag != "" {
		s.tags.Push(tag)
	}

	return matchers
}

func (s *Matchers) Add(rule ...contractroute.RouteRule) {
	matchers := make([]MatchEntry, 0, len(rule))

	for _, r := range rule {
		matchers = s.appendRule(matchers, r)
	}

	s.mu.Lock()
	s.matchers = append(s.matchers, matchers...)
	s.mu.Unlock()
}

func (s *Matchers) ChangePriority(source int, target int, operate string) {
	s.mu.Lock()
	switch operate {
	case "", "exchange":
		src := s.matchers[source]
		dst := s.matchers[target]
		s.matchers[source] = dst
		s.matchers[target] = src
	case "insert_before":
		s.matchers = InsertBefore(s.matchers, source, target)
	case "insert_after":
		s.matchers = InsertAfter(s.matchers, source, target)
	}
	s.mu.Unlock()
}

func (s *Matchers) Update(rules ...contractroute.RouteRule) {
	var ms []MatchEntry

	s.tags.Clear()
	s.list.ResetHostTrie()
	s.list.ResetProcessTrie()

	for _, v := range rules {
		ms = s.appendRule(ms, v)
	}

	s.mu.Lock()
	s.matchers = ms
	s.mu.Unlock()
}

func (s *Matchers) Match(ctx context.Context, addr netapi.Address) ModeEnum {
	s.mu.RLock()
	defer s.mu.RUnlock()

	store := netapi.GetContext(ctx)

	for _, v := range s.matchers {
		startMatch(store, v.name)
		if v.matcher.Match(ctx, addr) {
			return v.mode
		}
	}

	return ProxyMode
}

func (s *Matchers) Tags() iter.Seq[string] {
	return s.tags.Range
}

type List string

func (s List) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)

	if store.ConnOptions().HasList(string(s)) {
		recordMatch(store, fmt.Sprintf("List %s", string(s)), true)
		return true
	}

	recordMatch(store, fmt.Sprintf("List %s", string(s)), false)
	return false
}

func (s List) String() string {
	return string(s)
}

func ParseMatcher(lists *Lists, cc contractroute.RouteRule) Matcher {
	matchers := make([]Matcher, 0, len(cc.Rules))
	for _, expr := range cc.Rules {
		andMatchers := make([]Matcher, 0)
		for _, rule := range sortRule(flattenRuleExpr(expr)) {
			switch rule.Type {
			case "host":
				if rule.Host != nil {
					andMatchers = append(andMatchers, List(rule.Host.List))
					lists.AddNewHostList(rule.Host.List)
				}
			case "process":
				if rule.Process != nil {
					andMatchers = append(andMatchers, List(rule.Process.List))
					lists.AddNewProcessList(rule.Process.List)
				}
			case "inbound":
				if rule.Inbound != nil {
					names := append([]string(nil), rule.Inbound.Names...)
					if rule.Inbound.Name != "" {
						names = append(names, rule.Inbound.Name)
					}
					andMatchers = append(andMatchers, NewInbound(names...))
				}
			case "network":
				if rule.Network != nil {
					andMatchers = append(andMatchers, NewNetwork(rule.Network.Network))
				}
			case "port":
				if rule.Port != nil {
					andMatchers = append(andMatchers, NewPort(rule.Port.Ports))
				}
			case "geoip":
				if rule.GeoIP != nil {
					andMatchers = append(andMatchers, NewGeoip(rule.GeoIP.Countries))
				}
			}
		}

		if len(andMatchers) == 1 {
			matchers = append(matchers, andMatchers[0])
		} else {
			matchers = append(matchers, NewAnd(andMatchers...))
		}
	}

	if len(matchers) == 1 {
		return matchers[0]
	}

	return NewOr(cc.Name, matchers...)
}

func flattenRuleExpr(expr contractroute.RuleExpr) []contractroute.RuleExpr {
	if expr.Type == "all" {
		return expr.All
	}
	return []contractroute.RuleExpr{expr}
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
		case "inbound":
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
