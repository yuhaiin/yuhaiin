package resolver

import (
	"context"
	"errors"
	"net"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	rule "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

type accessFakeIPResolver struct {
	netapi.Resolver
	ip net.IP
}

func (r *accessFakeIPResolver) LookupIP(context.Context, string, ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return &netapi.IPs{A: []net.IP{r.ip}}, nil
}

func TestRecoveredFakeIPDoesNotBypassResolvedAccessPolicy(t *testing.T) {
	f := newFakeDNSForRoutes(t)
	ips, err := f.fake.LookupIP(t.Context(), "service.example", func(o *netapi.LookupIPOption) { o.Mode = netapi.ResolverModePreferIPv4 })
	if err != nil || len(ips.A) != 1 {
		t.Fatal(ips, err)
	}
	fake := netapi.ParseIPAddr("tcp", ips.A[0], 443)
	ctx := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}))
	ctx.SetInboundID("entry")
	original := f.RecoverDestination(ctx, fake)
	if !original.IsFqdn() || original.Hostname() != "service.example" {
		t.Fatal("lost original domain", original)
	}
	resolver := &accessFakeIPResolver{ip: net.IPv4(10, 1, 2, 3)}
	ctx.ConnOptions().Resolver().SetResolver(resolver)
	c := accesscontrol.New()
	defer c.Close()
	p, err := accesscontrol.Prepare(contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: "deny", Rules: []contract.Rule{
		{ID: "private", Action: "deny", Conditions: []rule.RuleExpr{{Type: "destination", Destination: &rule.DestinationExpr{CIDRs: []string{"10.0.0.0/8"}}}}},
		{ID: "domain", Action: "allow", Conditions: []rule.RuleExpr{{Type: "destination", Destination: &rule.DestinationExpr{Domains: []string{"service.example"}}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	c.Activate(p)
	if _, err := netapi.PinTrafficDestination(ctx, c, original); !errors.Is(err, netapi.ErrTrafficAccessDenied) {
		t.Fatal("FakeIP rebinding bypass", err)
	}
	resolver.ip = net.IPv4(192, 0, 2, 8)
	actual, err := netapi.PinTrafficDestination(ctx, c, original)
	if err != nil || actual.IsFqdn() || actual.Hostname() != "192.0.2.8" {
		t.Fatal("allowed recovered endpoint", actual, err)
	}
}
