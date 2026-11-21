package route

import (
	"testing"

	"codeberg.org/miekg/dns"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// The route records the decision behind the resolver choice, both for the
// cache-only probe and for the queued query that reuses its decision.
func TestDNSHistoryRecordsRouteDecision(t *testing.T) {
	matchers := newTestMatchers(t)
	if err := matchers.Update(contractroute.RouteRule{ID: "r-block", Name: "block everything", Mode: "block", Rules: []contractroute.RuleExpr{{Type: "always", Always: &contractroute.MatchAllExpr{}}}}); err != nil {
		t.Fatal(err)
	}
	router := NewRoute(nil, staticResolverBook{resolver: staticResolver{}}, matchers.list, nil)
	router.ms = matchers

	got := make(chan *netapi.DNSTraceData, 1)
	trace := netapi.NewDNSTrace("udp", netapi.DNSSourceHijack, func(d *netapi.DNSTraceData) { got <- d })
	ctx := netapi.WithDNSTrace(netapi.WithContext(t.Context()), trace)
	if _, err := router.Raw(ctx, netapi.DNSQuestion{Name: "ads.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}); err != nil {
		t.Fatal(err)
	}
	trace.Finish(nil)
	d := <-got
	if d.RouteMode != "block" || d.RouteRuleID != "r-block" || d.RouteRuleName != "block everything" || d.SelectionReason != "mode_default_resolver" || d.Source != netapi.DNSResolutionBlocked || d.Resolver != "block" {
		t.Fatalf("route = mode %q rule %q/%q reason %q source %q resolver %q", d.RouteMode, d.RouteRuleID, d.RouteRuleName, d.SelectionReason, d.Source, d.Resolver)
	}
}
