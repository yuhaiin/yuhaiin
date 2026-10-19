package route

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type gatewayTestDialer struct {
	target contract.Target
	mode   string
}

func (d *gatewayTestDialer) GetTarget(_ context.Context, _ string, mode string, target contract.Target) (netapi.Proxy, error) {
	d.mode = mode
	d.target = target
	return netapi.NewErrProxy(nil), nil
}
func gatewayRoute(t *testing.T, rules ...contract.RouteRule) *Route {
	t.Helper()
	matchers := newTestMatchers(t)
	if err := matchers.Update(rules...); err != nil {
		t.Fatal(err)
	}
	s := NewRoute(new(gatewayTestDialer), staticResolverBook{resolver: staticResolver{}}, matchers.list, nil)
	s.ms = matchers
	return s
}
func alwaysRule(id, mode string, target contract.Target) contract.RouteRule {
	return contract.RouteRule{ID: id, Name: id, Mode: mode, Target: target, Rules: []contract.RuleExpr{{Type: "always", Always: &contract.MatchAllExpr{}}}}
}

func TestGatewayGateKeepsNormalRuleOrderAndCachesDecision(t *testing.T) {
	for _, mode := range []string{"proxy", "direct", "block"} {
		t.Run(mode, func(t *testing.T) {
			selected := contract.Target{Type: "node", ID: "chosen-node"}
			router := gatewayRoute(t, alwaysRule("normal", mode, selected), alwaysRule("gateway", "gateway", contract.Target{Type: "gateway", ID: "g"}))
			handled := 0
			router.SetGatewayHandler(nil, func(*netapi.Context, *netapi.StreamMeta, string) bool { handled++; return true })
			count := 0
			router.matchers = append([]*matcher{{Name: "counter", Match: func(context.Context, netapi.Address) ModeEnum { count++; return Bypass }}}, router.matchers...)
			ctx := netapi.WithContext(t.Context())
			address, _ := netapi.ParseAddress("tcp", "example.com:443")
			if router.Intercept(ctx, &netapi.StreamMeta{Address: address}) {
				t.Fatal("earlier ordinary action was bypassed")
			}
			_, _, err := router.ResolveTCP(ctx, address, contract.Target{Type: "inherit_route"})
			if err != nil {
				t.Fatal(err)
			}
			dialer := router.d.(*gatewayTestDialer)
			if handled != 0 || count != 1 || dialer.mode != mode || dialer.target != selected {
				t.Fatalf("handled=%d route matches=%d mode=%s target=%+v", handled, count, dialer.mode, dialer.target)
			}
		})
	}
}
func TestGatewayGateFallbackAndHTTPReentry(t *testing.T) {
	for _, accept := range []bool{false, true} {
		t.Run(map[bool]string{false: "passthrough", true: "accepted"}[accept], func(t *testing.T) {
			router := gatewayRoute(t, alwaysRule("gateway", "gateway", contract.Target{Type: "gateway", ID: "g"}), alwaysRule("security", "block", contract.Target{}))
			handled := 0
			router.SetGatewayHandler(nil, func(ctx *netapi.Context, _ *netapi.StreamMeta, id string) bool {
				handled++
				if id != "g" {
					t.Fatal(id)
				}
				// Outgoing request must skip only Gateway actions and still hit L4 block.
				child := netapi.ForkContext(ctx)
				address, _ := netapi.ParseAddress("tcp", "example.com:443")
				_, _, _ = router.ResolveTCP(WithoutGateway(child), address, contract.Target{Type: "direct"})
				if router.d.(*gatewayTestDialer).mode != "block" {
					t.Fatal("Gateway bypassed block rule")
				}
				return accept
			})
			ctx := netapi.WithContext(t.Context())
			address, _ := netapi.ParseAddress("tcp", "example.com:443")
			if got := router.Intercept(ctx, &netapi.StreamMeta{Address: address}); got != accept {
				t.Fatal(got)
			}
			if !accept {
				_, _, _ = router.ResolveTCP(ctx, address, contract.Target{})
				if router.d.(*gatewayTestDialer).mode != "block" {
					t.Fatal("fallback lost block")
				}
			}
			if handled != 1 {
				t.Fatalf("recursive handoffs=%d", handled)
			}
		})
	}
}
func TestGatewayGateDoesNotReuseConnectionDecisionForHTTPFork(t *testing.T) {
	router := gatewayRoute(t, alwaysRule("normal", "proxy", contract.Target{Type: "node", ID: "old"}), alwaysRule("gateway", "gateway", contract.Target{Type: "gateway", ID: "g"}))
	router.SetGatewayHandler(nil, func(*netapi.Context, *netapi.StreamMeta, string) bool { return false })
	address, _ := netapi.ParseAddress("tcp", "example.com:443")
	ctx := netapi.WithContext(t.Context())
	router.Intercept(ctx, &netapi.StreamMeta{Address: address})
	// A request fork uses its explicit target, never the connection's cached node.
	child := netapi.ForkContext(ctx)
	_, _, _ = router.ResolveTCP(WithoutGateway(child), address, contract.Target{Type: "node", ID: "new"})
	if router.d.(*gatewayTestDialer).target.ID != "new" {
		t.Fatal("fork reused the admission target")
	}
}
func TestGatewayRulesAreTCPOnly(t *testing.T) {
	router := gatewayRoute(t, alwaysRule("gateway", "gateway", contract.Target{Type: "gateway", ID: "g"}), alwaysRule("normal", "direct", contract.Target{}))
	for _, network := range []string{"udp", "ip", ""} {
		address, _ := netapi.ParseAddress(network, "example.com:443")
		if mode := router.ms.Match(netapi.WithContext(t.Context()), address); mode.Mode() != ModeDirect {
			t.Fatalf("network=%q mode=%s", network, mode.Mode())
		}
	}
}

func TestGatewayActionsSkippedForPacketAndPingWithTCPAddress(t *testing.T) {
	for _, mode := range []string{"direct", "block"} {
		t.Run(mode, func(t *testing.T) {
			for _, operation := range []string{"packet", "ping"} {
				t.Run(operation, func(t *testing.T) {
					router := gatewayRoute(t, alwaysRule("gateway", "gateway", contract.Target{Type: "gateway", ID: "g"}), alwaysRule("normal", mode, contract.Target{}))
					// Yuubinsya decodes Ping destinations as TCP addresses. The
					// operation must govern Gateway eligibility, not that label.
					address, _ := netapi.ParseAddress("tcp", "example.com:443")
					ctx := netapi.WithContext(t.Context())
					if operation == "ping" {
						_, _ = router.Ping(ctx, address)
					} else {
						_, _ = router.PacketConn(ctx, address)
					}
					if got := router.d.(*gatewayTestDialer).mode; got != mode {
						t.Fatalf("%s selected %s, want %s", operation, got, mode)
					}
				})
			}
		})
	}
}

func TestGatewayActionsSkippedWhenInstalledDuringPacketOrPingDispatch(t *testing.T) {
	for _, operation := range []string{"packet", "ping"} {
		t.Run(operation, func(t *testing.T) {
			router := gatewayRoute(t, alwaysRule("old", "direct", contract.Target{}))
			installed := false
			router.matchers = append([]*matcher{{Name: "apply-between-fast-check-and-match", Match: func(context.Context, netapi.Address) ModeEnum {
				if !installed {
					installed = true
					if err := router.ms.Update(alwaysRule("gateway", "gateway", contract.Target{Type: "gateway", ID: "g"}), alwaysRule("normal", "block", contract.Target{})); err != nil {
						t.Fatal(err)
					}
				}
				return Bypass
			}}}, router.matchers...)
			address, _ := netapi.ParseAddress("tcp", "example.com:443")
			ctx := netapi.WithContext(t.Context())
			if operation == "ping" {
				_, _ = router.Ping(ctx, address)
			} else {
				_, _ = router.PacketConn(ctx, address)
			}
			if got := router.d.(*gatewayTestDialer).mode; got != "block" {
				t.Fatalf("%s selected %s after apply, want block", operation, got)
			}
		})
	}
}
func BenchmarkGatewayRouteGateDisabled(b *testing.B) {
	router := NewRoute(nil, nil, nil, nil)
	router.gatewayHandler = func(*netapi.Context, *netapi.StreamMeta, string) bool { return true }
	router.ms.hasGateway = atomic.Bool{}
	ctx := netapi.WithContext(b.Context())
	meta := new(netapi.StreamMeta)
	b.ReportAllocs()
	for b.Loop() {
		if router.Intercept(ctx, meta) {
			b.Fatal("disabled route gate accepted")
		}
	}
}

func TestGatewayActionUsesExistingHostListsAndRecoveredDestination(t *testing.T) {
	matchers := newTestMatchers(t)
	matchers.list.lists = staticRouteListBook{detail: contract.RouteListDetail{ID: "spotify", Name: "Spotify", Type: "host", Source: contract.ListSource{Type: "local", Local: &contract.LocalSource{Lists: []string{"*.spotify.com"}}}}}
	rule := alwaysRule("spotify-gateway", "gateway", contract.Target{Type: "gateway", ID: "g"})
	rule.Rules = []contract.RuleExpr{{Type: "host", Host: &contract.ListRef{List: "spotify"}}}
	if err := matchers.Update(rule); err != nil {
		t.Fatal(err)
	}
	router := NewRoute(new(gatewayTestDialer), staticResolverBook{resolver: staticResolver{}}, matchers.list, nil)
	router.ms = matchers
	handled := 0
	router.SetGatewayHandler(func(_ context.Context, address netapi.Address) netapi.Address {
		if !address.IsFqdn() {
			restored, _ := netapi.ParseAddress("tcp", "spclient.wg.spotify.com:443")
			return restored
		}
		return address
	}, func(*netapi.Context, *netapi.StreamMeta, string) bool { handled++; return true })
	for _, test := range []struct {
		host string
		want bool
	}{{"spotify.com", true}, {"spclient.wg.spotify.com", true}, {"region-spclient.spotify.com", true}, {"notspotify.com", false}, {"192.0.2.1", true}} {
		address, _ := netapi.ParseAddressPort("tcp", test.host, 443)
		if got := router.Intercept(netapi.WithContext(t.Context()), &netapi.StreamMeta{Address: address}); got != test.want {
			t.Fatalf("host=%s handled=%t", test.host, got)
		}
	}
	if handled != 4 {
		t.Fatal(handled)
	}
}

type gatewayProcessDumper struct{ calls int }

func (d *gatewayProcessDumper) ProcessName(string, netapi.Address, netapi.Address) (netapi.Process, error) {
	d.calls++
	return netapi.Process{Path: "/usr/bin/spotify", Pid: 1000000}, nil
}
func TestGatewayHTTPRequestsReuseKnownProcessMetadata(t *testing.T) {
	old := configuration.ProcessLookupMode.Load()
	configuration.ProcessLookupMode.Store("always")
	defer configuration.ProcessLookupMode.Store(old)
	router := gatewayRoute(t, alwaysRule("direct", "direct", contract.Target{}))
	dumper := new(gatewayProcessDumper)
	router.ProcessDumper = dumper
	ctx := netapi.WithContext(t.Context())
	source, _ := netapi.ParseAddress("tcp", "127.0.0.1:1000")
	destination, _ := netapi.ParseAddress("tcp", "192.0.2.1:443")
	ctx.Source = source
	ctx.Destination = destination
	router.PrepareGatewayContext(ctx, destination)
	_, _, _ = router.ResolveTCP(WithoutGateway(netapi.ForkContext(ctx)), destination, contract.Target{})
	if dumper.calls != 1 {
		t.Fatalf("lookups=%d", dumper.calls)
	}
}
