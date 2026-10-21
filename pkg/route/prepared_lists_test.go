package route

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestActionAndOrderChangesReuseMatchingIndexes(t *testing.T) {
	matchers := newTestMatchers(t)
	matchers.list.lists = staticRouteListBook{detail: contractroute.RouteListDetail{Name: "web", Type: "host", Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"example.com"}}}}}
	rule := contractroute.RouteRule{Name: "Sites", Mode: "direct", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "web"}}}}
	if err := matchers.Update(rule); err != nil {
		t.Fatal(err)
	}
	index := matchers.list.HostTrie()
	rule.Mode = "block"
	rule.Name = "Renamed"
	if err := matchers.Update(contractroute.RouteRule{Name: "Unused", Mode: "direct", Rules: []contractroute.RuleExpr{{Type: "network", Network: &contractroute.NetworkExpr{Network: "udp"}}}}, rule); err != nil {
		t.Fatal(err)
	}
	if matchers.list.HostTrie() != index {
		t.Fatal("action/order/name change rebuilt matching data")
	}
	ctx, _ := netapi.GetOrNewContext(t.Context())
	addr, err := netapi.ParseAddressPort("tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if mode := matchers.Match(ctx, addr); mode.Mode() != ModeBlock {
		t.Fatalf("new action was not applied: %s", mode.Mode())
	}
}

type updatingResolver struct {
	netapi.Resolver
	update func() error
}

func (r updatingResolver) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	if err := r.update(); err != nil {
		return nil, err
	}
	return r.Resolver.LookupIP(ctx, domain, opts...)
}

func TestResolverCanApplyRulesWithoutDeadlockingClassification(t *testing.T) {
	matchers := newTestMatchers(t)
	matchers.list.lists = staticRouteListBook{detail: contractroute.RouteListDetail{Name: "web", Type: "host", Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"1.2.3.0/24"}}}}}
	rule := contractroute.RouteRule{Name: "Sites", Mode: "direct", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "web"}}}}
	if err := matchers.Update(rule); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	ctx, state := netapi.GetOrNewContext(ctx)
	state.ConnOptions().Resolver().SetResolver(updatingResolver{Resolver: staticResolver{}, update: func() error { rule.Mode = "block"; return matchers.Update(rule) }})
	addr, err := netapi.ParseAddressPort("tcp", "unknown.invalid", 443)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan ModeEnum, 1)
	go func() { result <- matchers.Match(ctx, addr) }()
	select {
	case mode := <-result:
		if mode.Mode() != ModeBlock {
			t.Fatalf("classification did not retry with the new rules: %s", mode.Mode())
		}
	case <-ctx.Done():
		t.Fatal("classification held a rule/index lock across a resolver call")
	}
}

func TestFailedPreparationKeepsRunningRulesAndIndexes(t *testing.T) {
	matchers := newTestMatchers(t)
	matchers.list.lists = staticRouteListBook{detail: contractroute.RouteListDetail{Name: "web", Type: "host", Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"example.com"}}}}}
	rule := contractroute.RouteRule{Name: "Sites", Mode: "direct", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "web"}}}}
	if err := matchers.Update(rule); err != nil {
		t.Fatal(err)
	}
	index := matchers.list.HostTrie()
	rule.Mode = "block"
	rule.Rules[0].Host = &contractroute.ListRef{List: "missing"}
	if err := matchers.Update(rule); err == nil {
		t.Fatal("missing index data accepted")
	}
	if matchers.list.HostTrie() != index {
		t.Fatal("failed preparation replaced matching index")
	}
	ctx, _ := netapi.GetOrNewContext(t.Context())
	addr, err := netapi.ParseAddressPort("tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if mode := matchers.Match(ctx, addr); mode.Mode() != ModeDirect {
		t.Fatalf("failed preparation changed running action: %s", mode.Mode())
	}
}

func TestMatchingLabelsFollowAppliedSnapshotWithoutRebuildingIndexes(t *testing.T) {
	matchers := newTestMatchers(t)
	list := contractroute.RouteListDetail{ID: "stable-list", Name: "Work websites", Type: "host", Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"example.com"}}}}
	matchers.list.lists = staticRouteListBook{detail: list}
	rule := contractroute.RouteRule{ID: "stable-rule", Name: "Work traffic", Mode: "direct", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "stable-list"}}}}
	if err := matchers.Update(rule); err != nil {
		t.Fatal(err)
	}
	index := matchers.list.HostTrie()
	addr, err := netapi.ParseAddressPort("tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	first := netapi.WithContext(t.Context())
	matchers.Match(first, addr)
	list.Name = "Renamed websites"
	matchers.list.lists = staticRouteListBook{detail: list}
	if err := matchers.Update(rule); err != nil {
		t.Fatal(err)
	}
	if index != matchers.list.HostTrie() {
		t.Fatal("rename rebuilt index")
	}
	second := netapi.WithContext(t.Context())
	matchers.Match(second, addr)
	for _, tc := range []struct {
		context *netapi.Context
		name    string
	}{{first, "Work websites"}, {second, "Renamed websites"}} {
		if tc.context.ConnOptions().MatchedListNames()["stable-list"] != tc.name {
			t.Fatal("connection lost its applied labels")
		}
		entry := tc.context.MatchHistory()[0]
		if entry.RuleID != rule.ID || entry.History[0].ID != "stable-list" || entry.History[0].ListName != tc.name || !entry.History[0].Matched {
			t.Fatalf("trace = %+v", entry)
		}
	}
}

func TestUnavailableRemoteListSkipsNegatedRule(t *testing.T) {
	matchers := newTestMatchers(t)
	matchers.list.downloader = NewDownloader(t.TempDir(), nil)
	missing := (&url.URL{Scheme: "file", Path: filepath.Join(t.TempDir(), "missing.txt")}).String()
	matchers.list.lists = staticRouteListBook{detail: contractroute.RouteListDetail{
		ID: "telegram", Name: "Telegram", Type: "host",
		Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{missing}}},
	}}
	negated := contractroute.RouteRule{ID: "negated", Name: "not telegram", Mode: "block", Rules: []contractroute.RuleExpr{
		{Type: "not", Not: &contractroute.RuleExpr{Type: "host", Host: &contractroute.ListRef{List: "telegram"}}},
	}}
	independent := contractroute.RouteRule{ID: "independent", Name: "udp", Mode: "direct", Rules: []contractroute.RuleExpr{
		{Type: "network", Network: &contractroute.NetworkExpr{Network: "udp"}},
	}}
	if err := matchers.Update(negated, independent); err != nil {
		t.Fatal(err)
	}
	if len(matchers.skippedRules) != 1 || matchers.skippedRules[0].ID != negated.ID ||
		len(matchers.listIssues) != 1 || !matchers.listIssues[0].Unavailable {
		t.Fatalf("unavailable list rule not safely skipped: rules=%+v issues=%+v", matchers.skippedRules, matchers.listIssues)
	}
	udp, _ := netapi.ParseAddressPort("udp", "127.0.0.1", 53)
	if mode := matchers.Match(netapi.WithContext(t.Context()), udp); mode.Mode() != ModeDirect {
		t.Fatalf("independent UDP rule was skipped: %s", mode.Mode())
	}
	tcp, _ := netapi.ParseAddressPort("tcp", "127.0.0.1", 443)
	if mode := matchers.Match(netapi.WithContext(t.Context()), tcp); mode.Mode() != ModeProxy {
		t.Fatalf("NOT over unavailable list matched unexpectedly: %s", mode.Mode())
	}
}

func TestRemoteListPartialSourceFailureStillMatches(t *testing.T) {
	matchers := newTestMatchers(t)
	matchers.list.downloader = NewDownloader(t.TempDir(), nil)
	dir := t.TempDir()
	missing := (&url.URL{Scheme: "file", Path: filepath.Join(dir, "missing.txt")}).String()
	validPath := filepath.Join(dir, "working.txt")
	if err := os.WriteFile(validPath, []byte("valid.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := (&url.URL{Scheme: "file", Path: validPath}).String()
	matchers.list.lists = staticRouteListBook{detail: contractroute.RouteListDetail{
		ID: "telegram", Name: "Telegram", Type: "host",
		Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{missing, valid}}},
	}}
	rule := contractroute.RouteRule{ID: "remote", Mode: "block", Rules: []contractroute.RuleExpr{
		{Type: "host", Host: &contractroute.ListRef{List: "telegram"}},
	}}
	if err := matchers.Update(rule); err != nil {
		t.Fatal(err)
	}
	if len(matchers.skippedRules) != 0 || len(matchers.degradedRules) != 1 ||
		len(matchers.listIssues) != 1 || matchers.listIssues[0].Unavailable {
		t.Fatalf("partial source failure disabled healthy source: skipped=%+v degraded=%+v issues=%+v", matchers.skippedRules, matchers.degradedRules, matchers.listIssues)
	}
	addr, _ := netapi.ParseAddressPort("tcp", "valid.example", 443)
	if mode := matchers.Match(netapi.WithContext(t.Context()), addr); mode.Mode() != ModeBlock {
		t.Fatalf("healthy part of remote list did not match: %s", mode.Mode())
	}
	// A partially downloaded list cannot prove absence. NOT(list) must
	// therefore remain UNKNOWN when only some sources were loaded.
	not := contractroute.RuleExpr{Type: "not", Not: &rule.Rules[0]}
	rule.Rules = []contractroute.RuleExpr{not}
	if err := matchers.Update(rule); err != nil {
		t.Fatal(err)
	}
	unknown, _ := netapi.ParseAddressPort("tcp", "missing-from-loaded-part.example", 443)
	if mode := matchers.Match(netapi.WithContext(t.Context()), unknown); mode.Mode() != ModeProxy {
		t.Fatalf("NOT partial list incorrectly matched: %s", mode.Mode())
	}
	// Once the missing source becomes readable, the rule can again decide
	// absence and NOT(list) must match an unrelated address.
	missingPath := filepath.Join(dir, "missing.txt")
	if err := os.WriteFile(missingPath, []byte("other.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := matchers.Update(rule); err != nil {
		t.Fatal(err)
	}
	if len(matchers.degradedRules) != 0 {
		t.Fatalf("all sources recovered but rule is degraded: %+v", matchers.degradedRules)
	}
	if mode := matchers.Match(netapi.WithContext(t.Context()), unknown); mode.Mode() != ModeBlock {
		t.Fatalf("NOT complete list failed to match: %s", mode.Mode())
	}
}

func TestDegradedRuleKeepsHealthyORBranches(t *testing.T) {
	matchers := newTestMatchers(t)
	matchers.list.downloader = NewDownloader(t.TempDir(), nil)
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "ads.txt")
	if err := os.WriteFile(goodPath, []byte("ads.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodURL := (&url.URL{Scheme: "file", Path: goodPath}).String()
	missingPath := filepath.Join(dir, "malware.txt")
	missingURL := (&url.URL{Scheme: "file", Path: missingPath}).String()
	host := func(id string) contractroute.RuleExpr {
		return contractroute.RuleExpr{Type: "host", Host: &contractroute.ListRef{List: id}}
	}
	all := func(children ...contractroute.RuleExpr) contractroute.RuleExpr {
		return contractroute.RuleExpr{Type: "all", All: children}
	}
	any := func(children ...contractroute.RuleExpr) contractroute.RuleExpr {
		return contractroute.RuleExpr{Type: "any", Any: children}
	}
	not := func(child contractroute.RuleExpr) contractroute.RuleExpr {
		return contractroute.RuleExpr{Type: "not", Not: &child}
	}
	snapshot := plainstore.RouteSnapshot{
		Revision: 42,
		Lists: []contractroute.RouteListDetail{
			{ID: "ads", Name: "Ads", Type: "host", Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{goodURL}}}},
			{ID: "malware", Name: "Malware", Type: "host", Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{missingURL}}}},
		},
		Rules: []plainstore.RouteRuleEntry{
			{Rule: contractroute.RouteRule{ID: "block", Name: "Block unsafe", Mode: "block", Rules: []contractroute.RuleExpr{any(host("malware"), host("ads"))}}},
		},
	}
	activate := func(_ context.Context, revision uint64, install func()) error {
		if revision != snapshot.Revision {
			t.Fatalf("revision = %d, want %d", revision, snapshot.Revision)
		}
		install()
		return nil
	}
	apply := func() {
		t.Helper()
		if err := matchers.UpdateSnapshot(t.Context(), snapshot, activate, nil, func() {}); err != nil {
			t.Fatal(err)
		}
	}
	lookup := func(domain string) Mode {
		t.Helper()
		addr, err := netapi.ParseAddressPort("tcp", domain, 443)
		if err != nil {
			t.Fatal(err)
		}
		return matchers.Match(netapi.WithContext(t.Context()), addr).Mode()
	}
	apply()
	if len(matchers.skippedRules) != 0 || len(matchers.degradedRules) != 1 ||
		matchers.degradedRules[0].ID != "block" || !slices.Equal(matchers.degradedRules[0].ListIDs, []string{"malware"}) {
		t.Fatalf("OR degraded but disabled: skipped=%+v degraded=%+v", matchers.skippedRules, matchers.degradedRules)
	}
	if got := lookup("ads.example"); got != ModeBlock {
		t.Fatalf("healthy OR branch lost block action: %s", got)
	}
	if got := lookup("unrelated.example"); got != ModeProxy {
		t.Fatalf("unknown OR branch unexpectedly matched: %s", got)
	}

	// A healthy condition must remain usable inside nested AND/OR/NOT too.
	cases := []struct {
		name    string
		expr    contractroute.RuleExpr
		ads     bool
		unknown bool
	}{
		{"nested OR", all(any(host("malware"), host("ads")), not(host("malware"))), false, false},
		{"AND unknown", all(host("ads"), host("malware")), false, false},
		{"NOT unknown", not(host("malware")), false, false},
		{"NOT AND false", not(all(host("malware"), host("ads"))), false, true},
		{"NOT OR unknown", not(any(host("malware"), host("ads"))), false, false},
		{"double NOT unknown", not(not(host("malware"))), false, false},
		{"OR known true", any(not(all(host("malware"), host("ads"))), host("ads")), true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot.Rules = []plainstore.RouteRuleEntry{{Rule: contractroute.RouteRule{ID: "block", Mode: "block", Rules: []contractroute.RuleExpr{tc.expr}}}}
			apply()
			for _, check := range []struct {
				domain string
				want   bool
			}{{"ads.example", tc.ads}, {"unrelated.example", tc.unknown}} {
				got := lookup(check.domain)
				if (got == ModeBlock) != check.want {
					t.Fatalf("%s action %s, want block=%v", check.domain, got, check.want)
				}
			}
		})
	}

	// Once the missing list is available, the normal compiled matcher
	// becomes active again without editing or disabling the block rule.
	snapshot.Rules = []plainstore.RouteRuleEntry{{Rule: contractroute.RouteRule{ID: "block", Mode: "block", Rules: []contractroute.RuleExpr{any(host("malware"), host("ads"))}}}}
	if err := os.WriteFile(missingPath, []byte("malware.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	apply()
	if len(matchers.skippedRules) != 0 || len(matchers.degradedRules) != 0 || len(matchers.listIssues) != 0 {
		t.Fatalf("healthy list still degraded: skipped=%+v degraded=%+v issues=%+v", matchers.skippedRules, matchers.degradedRules, matchers.listIssues)
	}
	if got := lookup("malware.example"); got != ModeBlock {
		t.Fatalf("recovered list branch did not match: %s", got)
	}
}
