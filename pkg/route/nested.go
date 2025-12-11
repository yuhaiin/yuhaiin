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

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

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
		store.AddMatchHistory(inbound, ok)
		return ok
	}

	store.AddMatchHistory(inbound, false)
	return false
}

type Network struct {
	nt config.NetworkNetworkType
}

func NewNetwork(nt config.NetworkNetworkType) *Network {
	return &Network{
		nt: nt,
	}
}

func (s *Network) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)
	switch s.nt {
	case config.Network_tcp:
		ok := strings.HasPrefix(addr.Network(), "tcp")
		store.AddMatchHistory("Net TCP", ok)
		return ok
	case config.Network_udp:
		ok := strings.HasPrefix(addr.Network(), "udp")
		store.AddMatchHistory("Net UDP", ok)
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
	store.AddMatchHistory(fmt.Sprintf("Port %d", port), ok)
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
	store.AddMatchHistory(fmt.Sprintf("Geoip %s", geo), ok)
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
	mode    config.ModeEnum
	matcher Matcher
	name    string
}

type Matchers struct {
	mu       sync.RWMutex
	list     *Lists
	matchers []MatchEntry
	tags     *set.Set[string]
}

func NewMatchers(list *Lists) *Matchers {
	return &Matchers{
		list: list,
		tags: set.NewSet[string](),
	}
}

func (s *Matchers) Add(rule ...*config.Rulev2) {
	matchers := make([]MatchEntry, 0, len(rule))

	for _, r := range rule {
		matcher := ParseMatcher(s.list, r)
		matchers = append(matchers, MatchEntry{
			mode:    r.ToModeEnum(),
			matcher: matcher,
			name:    r.GetName(),
		})

		if tag := r.GetTag(); tag != "" {
			s.tags.Push(tag)
		}
	}

	s.mu.Lock()
	s.matchers = append(s.matchers, matchers...)
	s.mu.Unlock()
}

func (s *Matchers) ChangePriority(source int, target int, operate api.ChangePriorityRequestChangePriorityOperate) {
	s.mu.Lock()
	switch operate {
	case api.ChangePriorityRequest_Exchange:
		src := s.matchers[source]
		dst := s.matchers[target]
		s.matchers[source] = dst
		s.matchers[target] = src
	case api.ChangePriorityRequest_InsertBefore:
		s.matchers = InsertBefore(s.matchers, source, target)
	case api.ChangePriorityRequest_InsertAfter:
		s.matchers = InsertAfter(s.matchers, source, target)
	}
	s.mu.Unlock()
}

func (s *Matchers) Update(rules ...*config.Rulev2) {
	var ms []MatchEntry

	s.tags.Clear()
	s.list.ResetHostTrie()
	s.list.ResetProcessTrie()

	for _, v := range rules {
		ms = append(ms, MatchEntry{
			mode:    v.ToModeEnum(),
			matcher: ParseMatcher(s.list, v),
			name:    v.GetName(),
		})

		if tag := v.GetTag(); tag != "" {
			s.tags.Push(tag)
		}
	}

	s.mu.Lock()
	s.matchers = ms
	s.mu.Unlock()
}

func (s *Matchers) Match(ctx context.Context, addr netapi.Address) config.ModeEnum {
	s.mu.RLock()
	defer s.mu.RUnlock()

	store := netapi.GetContext(ctx)

	for _, v := range s.matchers {
		store.NewMatch(v.name)
		if v.matcher.Match(ctx, addr) {
			return v.mode
		}
	}

	return config.ProxyMode
}

func (s *Matchers) Tags() iter.Seq[string] {
	return s.tags.Range
}

type List string

func (s List) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)

	if store.ConnOptions().Lists().Has(string(s)) {
		store.AddMatchHistory(fmt.Sprintf("List %s", string(s)), true)
		return true
	}

	store.AddMatchHistory(fmt.Sprintf("List %s", string(s)), false)
	return false
}

func (s List) String() string {
	return string(s)
}

func ParseMatcher(lists *Lists, cc *config.Rulev2) Matcher {
	matchers := make([]Matcher, 0, len(cc.GetRules()))
	for _, v := range cc.GetRules() {
		andMatchers := make([]Matcher, 0, len(v.GetRules()))

		for _, rule := range sortRule(v.GetRules()) {
			switch rule.WhichObject() {
			case config.Rule_Host_case:
				andMatchers = append(andMatchers, List(rule.GetHost().GetList()))
				lists.AddNewHostList(rule.GetHost().GetList())

			case config.Rule_Process_case:
				andMatchers = append(andMatchers, List(rule.GetProcess().GetList()))
				lists.AddNewProcessList(rule.GetProcess().GetList())
			case config.Rule_Inbound_case:
				andMatchers = append(andMatchers, NewInbound(rule.GetInbound().GetNames()...))
			case config.Rule_Network_case:
				andMatchers = append(andMatchers, NewNetwork(rule.GetNetwork().GetNetwork()))
			case config.Rule_Port_case:
				andMatchers = append(andMatchers, NewPort(rule.GetPort().GetPorts()))
			case config.Rule_Geoip_case:
				andMatchers = append(andMatchers, NewGeoip(rule.GetGeoip().GetCountries()))
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

	return NewOr(cc.GetName(), matchers...)
}

func sortRule(rules []*config.Rule) []*config.Rule {
	if len(rules) <= 1 {
		return rules
	}

	getNo := func(rule *config.Rule) int {
		switch rule.WhichObject() {
		case config.Rule_Port_case, config.Rule_Network_case:
			return 1
		case config.Rule_Process_case:
			return 2
		case config.Rule_Inbound_case:
			return 3
		case config.Rule_Geoip_case:
			return 4
		case config.Rule_Host_case:
			return 5
		default:
			return math.MaxInt
		}
	}

	slices.SortFunc(rules,
		func(a, b *config.Rule) int { return cmp.Compare(getNo(a), getNo(b)) })

	return rules
}
