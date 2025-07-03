package route

import (
	"cmp"
	"context"
	"math"
	"slices"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/list"
)

type Matcher interface {
	Match(context.Context, netapi.Address) bool
}

type Inbound struct {
	store *list.Set[string]
}

func NewInbound(inbounds ...string) *Inbound {
	i := &Inbound{
		store: list.NewSet[string](),
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
	nt bypass.NetworkNetworkType
}

func NewNetwork(nt bypass.NetworkNetworkType) *Network {
	return &Network{
		nt: nt,
	}
}

func (s *Network) Match(ctx context.Context, addr netapi.Address) bool {
	store := netapi.GetContext(ctx)
	switch s.nt {
	case bypass.Network_tcp:
		ok := strings.HasPrefix(addr.Network(), "tcp")
		store.AddMatchHistory("Net TCP", ok)
		return ok
	case bypass.Network_udp:
		ok := strings.HasPrefix(addr.Network(), "udp")
		store.AddMatchHistory("Net UDP", ok)
		return ok
	default:
		return false
	}
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

func ParseMatcher(lists *Lists, config *bypass.Rulev2) Matcher {
	matchers := make([]Matcher, 0, len(config.GetRules()))
	for _, v := range config.GetRules() {
		andMatchers := make([]Matcher, 0, len(v.GetRules()))

		for _, rule := range sortRule(v.GetRules()) {
			switch rule.WhichObject() {
			case bypass.Rule_Host_case:
				andMatchers = append(andMatchers, NewListsMatcher(lists, rule.GetHost().GetList()))
			case bypass.Rule_Process_case:
				andMatchers = append(andMatchers, NewListsMatcher(lists, rule.GetProcess().GetList()))
			case bypass.Rule_Inbound_case:
				andMatchers = append(andMatchers, NewInbound(rule.GetInbound().GetNames()...))
			case bypass.Rule_Network_case:
				andMatchers = append(andMatchers, NewNetwork(rule.GetNetwork().GetNetwork()))
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

	return NewOr(config.GetName(), matchers...)
}

func sortRule(rules []*bypass.Rule) []*bypass.Rule {
	getNo := func(rule *bypass.Rule) int {
		switch rule.WhichObject() {
		case bypass.Rule_Process_case:
			return 1
		case bypass.Rule_Inbound_case:
			return 2
		case bypass.Rule_Host_case:
			return 3
		default:
			return math.MaxInt
		}
	}

	slices.SortFunc(rules,
		func(a, b *bypass.Rule) int { return cmp.Compare(getNo(a), getNo(b)) })

	return rules
}

type MatchEntry struct {
	mode    bypass.ModeEnum
	matcher Matcher
	name    string
}

type Matchers struct {
	mu       sync.RWMutex
	list     *Lists
	matchers []MatchEntry
	tags     map[string]struct{}
}

func NewMatchers(list *Lists) *Matchers {
	return &Matchers{
		list: list,
	}
}

func (s *Matchers) Add(rule *bypass.Rulev2) {
	matcher := ParseMatcher(s.list, rule)

	s.mu.Lock()
	s.matchers = append(s.matchers, MatchEntry{
		mode:    rule.ToModeEnum(),
		matcher: matcher,
		name:    rule.GetName(),
	})
	if rule.GetTag() != "" {
		s.tags[rule.GetTag()] = struct{}{}
	}
	s.mu.Unlock()
}

func (s *Matchers) ChangePriority(source int, target int, operate gc.ChangePriorityRequestChangePriorityOperate) {
	s.mu.Lock()
	switch operate {
	case gc.ChangePriorityRequest_Exchange:
		src := s.matchers[source]
		dst := s.matchers[target]
		s.matchers[source] = dst
		s.matchers[target] = src
	case gc.ChangePriorityRequest_InsertBefore:
		s.matchers = InsertBefore(s.matchers, source, target)
	case gc.ChangePriorityRequest_InsertAfter:
		s.matchers = InsertAfter(s.matchers, source, target)
	}
	s.mu.Unlock()
}

func (s *Matchers) Update(rules []*bypass.Rulev2) {
	var ms []MatchEntry
	tags := map[string]struct{}{}
	for _, v := range rules {
		ms = append(ms, MatchEntry{
			mode:    v.ToModeEnum(),
			matcher: ParseMatcher(s.list, v),
			name:    v.GetName(),
		})

		if v.GetTag() != "" {
			tags[v.GetTag()] = struct{}{}
		}
	}

	s.mu.Lock()
	s.matchers = ms
	s.tags = tags
	s.mu.Unlock()
}

func (s *Matchers) Match(ctx context.Context, addr netapi.Address) bypass.ModeEnum {
	s.mu.RLock()
	defer s.mu.RUnlock()

	store := netapi.GetContext(ctx)

	for _, v := range s.matchers {
		store.NewMatch(v.name)
		if v.matcher.Match(ctx, addr) {
			return v.mode
		}
	}

	return bypass.Proxy
}

func (s *Matchers) Tags() map[string]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.tags
}
