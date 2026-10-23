package accesscontrol

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	rule "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func subject(ctx context.Context, user string, groups ...string) netapi.TrafficSubject {
	return netapi.TrafficSubject{External: true, InboundID: "entry", Identity: &proxyauth.Identity{UserID: user, CredentialID: user + "-phone", GroupIDs: groups, Context: ctx}}
}
func address(t testing.TB, network, value string) netapi.Address {
	t.Helper()
	a, err := netapi.ParseAddress(network, value)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func install(t testing.TB, c *Controller, config contract.Config) {
	t.Helper()
	p, err := Prepare(config)
	if err != nil {
		t.Fatal(err)
	}
	c.Activate(p)
}
func config(rules ...contract.Rule) contract.Config {
	return contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: "deny", Rules: rules}
}
func groupRule(id, action, group string, conditions ...rule.RuleExpr) contract.Rule {
	return contract.Rule{ID: id, Action: action, Conditions: []rule.RuleExpr{{Type: "all", All: append([]rule.RuleExpr{{Type: "group", Group: &rule.IdentityExpr{IDs: []string{group}}}}, conditions...)}}}
}

func TestOrderedIdentityAndResolvedDestinationAuthorization(t *testing.T) {
	c := New()
	defer c.Close()
	cfg := config(
		contract.Rule{ID: "deny-private", Action: "deny", Conditions: []rule.RuleExpr{{Type: "destination", Destination: &rule.DestinationExpr{CIDRs: []string{"10.0.0.0/8", "::ffff:192.168.0.0/112"}}}}},
		groupRule("finance", "allow", "finance", rule.RuleExpr{Type: "destination", Destination: &rule.DestinationExpr{Domains: []string{"*.example.com"}}}, rule.RuleExpr{Type: "network", Network: &rule.NetworkExpr{Network: "tcp"}}, rule.RuleExpr{Type: "port", Port: &rule.PortExpr{Ports: "443"}}),
	)
	install(t, c, cfg)
	original := address(t, "tcp", "service.example.com:443")
	public := address(t, "tcp", "203.0.113.7:443")
	for _, tt := range []struct {
		name     string
		subject  netapi.TrafficSubject
		resolved netapi.Address
		allow    bool
	}{
		{"allowed", subject(t.Context(), "alice", "engineering", "finance"), public, true},
		{"no-identity", netapi.TrafficSubject{External: true, InboundID: "entry"}, public, false},
		{"other-group", subject(t.Context(), "bob", "engineering"), public, false},
		{"rebind-private", subject(t.Context(), "alice", "finance"), address(t, "tcp", "10.1.2.3:443"), false},
		{"mapped-private", subject(t.Context(), "alice", "finance"), address(t, "tcp", "192.168.1.4:443"), false},
		{"unresolved", subject(t.Context(), "alice", "finance"), original, false},
		{"port", subject(t.Context(), "alice", "finance"), address(t, "tcp", "203.0.113.7:22"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := c.Preview(tt.subject, original, tt.resolved)
			if d.Allowed != tt.allow {
				t.Fatalf("decision=%+v", d)
			}
		})
	}
	cfg.DefaultAction = "allow"
	install(t, c, cfg)
	if d := c.Preview(netapi.TrafficSubject{External: true, InboundID: "entry"}, original, public); d.Allowed {
		t.Fatal("default allow admitted missing identity")
	}
	if err := c.Preflight(netapi.TrafficSubject{}); err != nil {
		t.Fatal("resolver-internal traffic was misclassified as an authenticated user", err)
	}
	cfg.Scope = contract.Scope{Inbounds: []string{"managed"}}
	install(t, c, cfg)
	if d := c.Preview(netapi.TrafficSubject{External: true, InboundID: "entry"}, original, public); !d.Allowed || d.Managed {
		t.Fatalf("explicit unmanaged scope=%+v", d)
	}
}

func TestPolicyUpdatesRevokeOnlyAffectedSessionsAndReleaseTargets(t *testing.T) {
	c := New()
	defer c.Close()
	initial := config(groupRule("finance", "allow", "finance"), groupRule("engineering", "allow", "engineering"))
	install(t, c, initial)
	dst := address(t, "udp", "203.0.113.7:443")
	var financeClosed, engineeringClosed atomic.Int32
	a, err := c.NewSession(subject(t.Context(), "alice", "finance"), func(error) { financeClosed.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.NewSession(subject(t.Context(), "bob", "engineering"), func(error) { engineeringClosed.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	if err := a.Authorize(dst, dst); err != nil {
		t.Fatal(err)
	}
	if err := b.Authorize(dst, dst); err != nil {
		t.Fatal(err)
	}
	next := config(groupRule("engineering", "allow", "engineering"))
	next.Revision = 2
	install(t, c, next)
	if financeClosed.Load() != 1 || engineeringClosed.Load() != 0 {
		t.Fatal("policy update revoked unrelated sessions")
	}
	if err := a.Authorize(dst, dst); err == nil {
		t.Fatal("revoked authorization reused")
	}
	if err := b.Authorize(dst, dst); err != nil {
		t.Fatal("unrelated stream lost its authorization")
	}
	a.Close()
	a.Close()
	if c.Status().Sessions != 1 || c.targets.Load() != 1 {
		t.Fatalf("resources leaked or double released: %+v targets=%d", c.Status(), c.targets.Load())
	}
	b.Close()
	if c.targets.Load() != 0 {
		t.Fatal("target accounting leaked")
	}
}

func TestEnablePolicyClosesUnattributedExistingSessions(t *testing.T) {
	c := New()
	defer c.Close()
	var closed atomic.Int32
	s, err := c.NewSession(netapi.TrafficSubject{External: true, InboundID: "entry"}, func(error) { closed.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	dst := address(t, "tcp", "203.0.113.2:443")
	if err := s.Authorize(dst, dst); err != nil {
		t.Fatal(err)
	}
	install(t, c, config(contract.Rule{ID: "all", Action: "allow", Conditions: []rule.RuleExpr{{Type: "always", Always: &rule.MatchAllExpr{}}}}))
	if closed.Load() != 1 || c.Status().Sessions != 0 {
		t.Fatalf("old anonymous session survived policy activation: %+v", c.Status())
	}
}

func TestCredentialCancellationReleasesSessionExactlyOnce(t *testing.T) {
	c := New()
	defer c.Close()
	ctx, cancel := context.WithCancel(t.Context())
	closed := make(chan struct{})
	s, err := c.NewSession(subject(ctx, "alice"), func(error) { close(closed) })
	if err != nil {
		t.Fatal(err)
	}
	dst := address(t, "tcp", "203.0.113.2:443")
	if err := s.Authorize(dst, dst); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("credential revocation retained the session")
	}
	s.Close()
	s.Close()
	if c.Status().Sessions != 0 || c.targets.Load() != 0 {
		t.Fatal("credential revocation leaked admission")
	}
}

func TestPrepareRejectsAmbiguousScopesAndUnavailableConditions(t *testing.T) {
	for _, cfg := range []contract.Config{
		config(contract.Rule{ID: "ports", Action: "allow", Conditions: []rule.RuleExpr{{Type: "port", Port: &rule.PortExpr{Ports: "1-65535"}}}}),
		{Enabled: true, DefaultAction: "deny"},
		{Enabled: true, Scope: contract.Scope{AllInbounds: true, Inbounds: []string{"entry"}}, DefaultAction: "deny"},
		{Enabled: true, Scope: contract.Scope{AllInbounds: true}},
		config(contract.Rule{ID: "a", Action: "allow", Conditions: []rule.RuleExpr{{Type: "not", Not: &rule.RuleExpr{Type: "host", Host: &rule.ListRef{List: "unavailable"}}}}}),
		config(contract.Rule{ID: "a", Action: "allow", Conditions: []rule.RuleExpr{{Type: "destination", Destination: &rule.DestinationExpr{CIDRs: []string{"garbage"}}}}}),
	} {
		if _, err := Prepare(cfg); err == nil {
			t.Fatalf("accepted invalid policy: %+v", cfg)
		}
	}
	cfg := config(groupRule("finance", "allow", "finance"))
	p, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Rules[0].Conditions[0].All[0].Group.IDs[0] = "changed"
	c := New()
	defer c.Close()
	c.Activate(p)
	dst := address(t, "tcp", "203.0.113.2:443")
	if err := c.Check(subject(t.Context(), "alice", "finance"), dst, dst); err != nil {
		t.Fatal("caller mutated active policy", err)
	}
}

func TestConcurrentAuthorizationUpdatesAndCloses(t *testing.T) {
	c := New()
	defer c.Close()
	install(t, c, config(groupRule("all", "allow", "finance")))
	dst := address(t, "udp", "203.0.113.2:443")
	var wg sync.WaitGroup
	for n := range 16 {
		wg.Go(func() {
			for range 64 {
				s, err := c.NewSession(subject(t.Context(), fmt.Sprint(n), "finance"), func(error) {})
				if err == nil {
					_ = s.Authorize(dst, dst)
					s.Close()
				}
			}
		})
	}
	for range 10 {
		install(t, c, config(groupRule("all", "allow", "finance")))
	}
	wg.Wait()
	if c.Status().Sessions != 0 || c.targets.Load() != 0 {
		t.Fatalf("concurrent release=%+v targets=%d", c.Status(), c.targets.Load())
	}
}

func BenchmarkAccessPolicyEvaluation(b *testing.B) {
	c := New()
	defer c.Close()
	install(b, c, config(groupRule("finance", "allow", "finance", rule.RuleExpr{Type: "destination", Destination: &rule.DestinationExpr{CIDRs: []string{"203.0.113.0/24"}}}, rule.RuleExpr{Type: "network", Network: &rule.NetworkExpr{Network: "udp"}}, rule.RuleExpr{Type: "port", Port: &rule.PortExpr{Ports: "443"}})))
	owner := subject(b.Context(), "alice", "finance")
	dst := address(b, "udp", "203.0.113.2:443")
	b.ReportAllocs()
	for b.Loop() {
		if err := c.Check(owner, dst, dst); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAccessCachedDatagram(b *testing.B) {
	c := New()
	defer c.Close()
	install(b, c, config(groupRule("finance", "allow", "finance")))
	s, err := c.NewSession(subject(b.Context(), "alice", "finance"), func(error) {})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	dst := address(b, "udp", "203.0.113.2:443")
	actual := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 2), Port: 443}
	if err := s.Authorize(dst, actual); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := s.Authorize(dst, actual); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCachedAuthorizationHasNoPerDatagramAllocation(t *testing.T) {
	c := New()
	defer c.Close()
	install(t, c, config(groupRule("finance", "allow", "finance")))
	s, err := c.NewSession(subject(t.Context(), "alice", "finance"), func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dst := netapi.ParseNetipAddrPort("udp", netip.MustParseAddrPort("203.0.113.2:443"))
	actual := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 2), Port: 443}
	if err := s.Authorize(dst, actual); err != nil {
		t.Fatal(err)
	}
	if got := testing.AllocsPerRun(1000, func() {
		if err := s.Authorize(dst, actual); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Fatalf("cached datagram allocations=%v", got)
	}
}

func TestFullPolicyEvaluationHasNoAllocation(t *testing.T) {
	c := New()
	defer c.Close()
	install(t, c, config(groupRule("finance", "allow", "finance", rule.RuleExpr{Type: "destination", Destination: &rule.DestinationExpr{CIDRs: []string{"203.0.113.0/24"}}}, rule.RuleExpr{Type: "network", Network: &rule.NetworkExpr{Network: "udp"}}, rule.RuleExpr{Type: "port", Port: &rule.PortExpr{Ports: "443"}})))
	owner := subject(t.Context(), "alice", "finance")
	dst := address(t, "udp", "203.0.113.2:443")
	if n := testing.AllocsPerRun(1000, func() {
		if err := c.Check(owner, dst, dst); err != nil {
			t.Fatal(err)
		}
	}); n != 0 {
		t.Fatal("policy evaluation allocations", n)
	}
}

func TestMultipleTargetsAreBoundedAndAllRevalidated(t *testing.T) {
	c := New()
	defer c.Close()
	install(t, c, config(groupRule("finance", "allow", "finance")))
	var revoked atomic.Int32
	s, err := c.NewSession(subject(t.Context(), "alice", "finance"), func(error) { revoked.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	for port := range maxSessionTargets {
		dst := netapi.ParseNetipAddrPort("udp", netip.AddrPortFrom(netip.MustParseAddr("203.0.113.2"), uint16(port+1)))
		if err := s.Authorize(dst, dst); err != nil {
			t.Fatal(port, err)
		}
	}
	overflow := address(t, "udp", "203.0.113.2:65535")
	if err := s.Authorize(overflow, overflow); err == nil || c.targets.Load() != maxSessionTargets {
		t.Fatal("target capacity bypass", err, c.targets.Load())
	}
	install(t, c, config(contract.Rule{ID: "deny-last", Action: "deny", Conditions: []rule.RuleExpr{{Type: "port", Port: &rule.PortExpr{Ports: "1024"}}}}, groupRule("finance", "allow", "finance")))
	if revoked.Load() != 1 || c.Status().Sessions != 0 || c.targets.Load() != 0 {
		t.Fatal("secondary target not revoked or released", revoked.Load(), c.Status(), c.targets.Load())
	}
	s.Close()
	if c.targets.Load() != 0 {
		t.Fatal("double release")
	}
}

func TestProtectedPolicyRejectsMismatchedOrUnknownTransport(t *testing.T) {
	c := New()
	defer c.Close()
	cfg := config()
	cfg.DefaultAction = "allow"
	install(t, c, cfg)
	owner := subject(t.Context(), "alice")
	tcp := address(t, "tcp", "203.0.113.2:443")
	udp := address(t, "udp", "203.0.113.2:443")
	if d := c.Preview(owner, tcp, udp); d.Allowed || d.Reason != "invalid_transport" {
		t.Fatal("UDP impersonated TCP", d)
	}
	if d := c.Preview(owner, nil, address(t, "ip", "203.0.113.2:443")); d.Allowed {
		t.Fatal("unsupported transport allowed", d)
	}
	s, err := c.NewSession(owner, func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	real := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 2), Port: 443}
	if err := s.Authorize(udp, real); err != nil {
		t.Fatal(err)
	}
	if err := s.Authorize(tcp, real); err == nil {
		t.Fatal("cached UDP target impersonated TCP")
	}
}
