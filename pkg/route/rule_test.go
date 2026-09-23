package route

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

type staticRuleBook []plainstore.RouteRuleEntry

func (s staticRuleBook) ListRules(context.Context) ([]plainstore.RouteRuleEntry, error) {
	return s, nil
}

type staticRouteListBook struct {
	detail contractroute.RouteListDetail
}

func (s staticRouteListBook) ListRouteListDetails(context.Context) ([]contractroute.RouteListDetail, error) {
	return []contractroute.RouteListDetail{s.detail}, nil
}

func (s staticRouteListBook) GetRouteList(_ context.Context, name string) (contractroute.RouteListDetail, error) {
	if name != s.detail.Name {
		return contractroute.RouteListDetail{}, errors.New("route list not found")
	}
	return s.detail, nil
}

func (staticRouteListBook) SaveRouteList(context.Context, contractroute.RouteListDetail, int64) error {
	return nil
}

func TestRulesStartupBuildsHostIndexBeforeTestingRoutes(t *testing.T) {
	oldDataDir := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(oldDataDir) })

	lists := NewLists(staticRouteListBook{detail: contractroute.RouteListDetail{
		Name: "direct_2_host",
		Type: "host",
		Source: contractroute.ListSource{
			Type:  "local",
			Local: &contractroute.LocalSource{Lists: []string{"*.cdn.hf.co", "10.0.0.0/8"}},
		},
	}}, &listSettingsStub{value: RouteListSettings{HostIndexDisk: true}}, t.TempDir())
	t.Cleanup(func() {
		if err := lists.Close(); err != nil {
			t.Logf("close lists failed: %v", err)
		}
	})

	route := NewRoute(nil, staticResolverBook{resolver: staticResolver{}}, lists, nil)
	rules := NewRules(staticRuleBook{{Rule: contractroute.RouteRule{
		Name:  "direct",
		Mode:  "direct",
		Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "direct_2_host"}}},
	}}}, nil, route)
	response, err := rules.TestContract(context.Background(), "us.aws.cdn.hf.co")
	if err != nil {
		t.Fatal(err)
	}
	if response.Mode != "direct" || !slices.Contains(response.Lists, "direct_2_host") {
		t.Fatalf("startup route test = %+v", response)
	}

	addr, err := netapi.ParseAddressPort("", "us.aws.cdn.hf.co", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := lists.HostTrie().Search(context.Background(), addr); !slices.Contains(got, "direct_2_host") {
		t.Fatalf("startup host index did not match nested wildcard: %v", got)
	}
	segments, err := filepath.Glob(filepath.Join(lists.hostTrie.cache.Dir(), "segment-*.mmap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) == 0 {
		t.Fatal("startup disk host index retained its completed builder in memory")
	}
	cidrSegments, err := filepath.Glob(filepath.Join(lists.hostTrie.cache.Dir(), "segment-*.cidr"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cidrSegments) == 0 {
		t.Fatal("startup disk host index retained its completed CIDR builder in memory")
	}
	ipAddr, err := netapi.ParseAddressPort("", "10.1.2.3", 80)
	if err != nil {
		t.Fatal(err)
	}
	if got := lists.HostTrie().Search(context.Background(), ipAddr); !slices.Contains(got, "direct_2_host") {
		t.Fatalf("startup disk host index did not match CIDR list: %v", got)
	}
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
		hostTrie:    newHostTrie(t.TempDir(), false),
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
		hostTrie:    newHostTrie(t.TempDir(), false),
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
	if err := lists.hostTrie.Add(func(yield func(string) bool) {
		yield("1.2.3.0/24")
	}, "CN"); err != nil {
		t.Fatal(err)
	}

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

func (staticResolver) Raw(context.Context, netapi.DNSQuestion) (*dns.Msg, error) {
	return nil, nil
}

func (staticResolver) Close() error { return nil }

func (staticResolver) Name() string { return "static" }
