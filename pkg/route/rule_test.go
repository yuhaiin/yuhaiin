package route

import (
	"context"
	"net"
	"testing"
	"time"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/miekg/dns"
)

type staticRuleBook []plainstore.RouteRuleEntry

func (s staticRuleBook) ListRules(context.Context) ([]plainstore.RouteRuleEntry, error) {
	return s, nil
}

func TestRuleChangesCanBeScheduledAndAppliedImmediately(t *testing.T) {
	matchers := newTestMatchers(t)
	rules := &Rules{
		rules: staticRuleBook{{Rule: contractroute.RouteRule{Name: "scheduled", Mode: "direct"}}},
		route: &Route{ms: matchers},
	}

	before := time.Now().UnixMilli()
	rules.ScheduleApply()
	status, err := rules.ActivationStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.ApplyAt < before+59_000 || status.ApplyAt > before+61_000 {
		t.Fatalf("unexpected scheduled apply time: %d", status.ApplyAt)
	}

	if err := rules.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err = rules.ActivationStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.ApplyAt != 0 {
		t.Fatalf("apply time was not cleared: %d", status.ApplyAt)
	}
	if len(matchers.matchers) != 1 || matchers.matchers[0].name != "scheduled" {
		t.Fatalf("stored rules were not applied: %#v", matchers.matchers)
	}
}

func newTestMatchers(t *testing.T) *Matchers {
	t.Helper()

	lists := &Lists{
		hostTrie:    newHostTrie(t.TempDir()),
		processTrie: newProcessTrie(),
	}

	t.Cleanup(func() {
		if err := lists.Close(); err != nil {
			t.Logf("close lists failed: %v", err)
		}
	})

	return NewMatchers(lists)
}

func TestChangePriority(t *testing.T) {
	t.Run("insertBefore", func(t *testing.T) {
		src := []string{"a", "b", "c", "d", "e"}
		t.Log(assert.ObjectsAreEqual([]string{"a", "d", "b", "c", "e"}, InsertBefore(src, 3, 1)))
		t.Log(assert.ObjectsAreEqual([]string{"d", "a", "b", "c", "e"}, InsertBefore(src, 3, 0)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "c", "d", "e"}, InsertBefore(src, 3, 4)))
	})

	t.Run("insertAfter", func(t *testing.T) {
		src := []string{"a", "b", "c", "d", "e"}
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "d", "c", "e"}, InsertAfter(src, 3, 1)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "d", "b", "c", "e"}, InsertAfter(src, 3, 0)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "c", "e", "d"}, InsertAfter(src, 3, 4)))
	})
}

func TestDisabledRuleSkippedBeforeParsing(t *testing.T) {
	matchers := newTestMatchers(t)

	matchers.Update(contractroute.RouteRule{
		Name:     "disabled-host-list",
		Disabled: true,
		Rules: []contractroute.RuleExpr{
			{Type: "host", Host: &contractroute.ListRef{List: "disabled-list"}},
		},
	})

	if len(matchers.matchers) != 0 {
		t.Fatalf("disabled rule should not be added to runtime matchers, got %d", len(matchers.matchers))
	}
}

func TestMatcherRebuildSkipsDisabledRules(t *testing.T) {
	matchers := newTestMatchers(t)

	matchers.Update(
		contractroute.RouteRule{Name: "enabled-a"},
		contractroute.RouteRule{
			Name:     "disabled-b",
			Disabled: true,
			Rules: []contractroute.RuleExpr{
				{Type: "host", Host: &contractroute.ListRef{List: "disabled-list"}},
			},
		},
		contractroute.RouteRule{Name: "enabled-c"},
	)

	if len(matchers.matchers) != 2 {
		t.Fatalf("disabled rule should be skipped during rebuild, got %d matchers", len(matchers.matchers))
	}
	if matchers.matchers[0].name != "enabled-a" || matchers.matchers[1].name != "enabled-c" {
		t.Fatalf("unexpected runtime matcher order: %#v", matchers.matchers)
	}
}

func TestRuleTestContractSharesNetapiContext(t *testing.T) {
	lists := &Lists{
		hostTrie:    newHostTrie(t.TempDir()),
		processTrie: newProcessTrie(),
	}
	t.Cleanup(func() {
		if err := lists.Close(); err != nil {
			t.Logf("close lists failed: %v", err)
		}
	})
	route := NewRoute(nil, staticResolverBook{resolver: staticResolver{}}, lists, nil)
	route.ms.Update(contractroute.RouteRule{
		Name: "cn-direct",
		Mode: "direct",
		Rules: []contractroute.RuleExpr{
			{Type: "host", Host: &contractroute.ListRef{List: "CN"}},
		},
	})
	lists.hostTrie.Add(func(yield func(string) bool) {
		yield("1.2.3.0/24")
	}, "CN")

	rules := &Rules{route: route}
	resp, err := rules.TestContract(context.Background(), "www.baidu.com")
	if err != nil {
		t.Fatalf("test route failed: %v", err)
	}
	if resp.Mode != "direct" {
		t.Fatalf("expected direct mode, got %#v", resp)
	}
	if !assert.ObjectsAreEqual([]string{"CN"}, resp.Lists) {
		t.Fatalf("expected CN list match, got %#v", resp.Lists)
	}
	if !assert.ObjectsAreEqual([]string{"1.2.3.4"}, resp.IPs) {
		t.Fatalf("expected resolved IPs, got %#v", resp.IPs)
	}
}

type staticResolverBook struct {
	resolver netapi.Resolver
}

func (s staticResolverBook) Get(_, _ string) netapi.Resolver {
	return s.resolver
}

type staticResolver struct{}

func (staticResolver) LookupIP(context.Context, string, ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return &netapi.IPs{A: []net.IP{net.ParseIP("1.2.3.4")}}, nil
}

func (staticResolver) Raw(context.Context, dns.Question) (dns.Msg, error) {
	return dns.Msg{}, nil
}

func (staticResolver) Close() error { return nil }

func (staticResolver) Name() string { return "static" }
