package route

import (
	"context"
	"fmt"
	"slices"
	"testing"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func TestNestedAuthenticatedIdentityConditions(t *testing.T) {
	user := contract.RuleExpr{Type: "user", User: &contract.IdentityExpr{IDs: []string{"alice", "bob"}}}
	group := contract.RuleExpr{Type: "group", Group: &contract.IdentityExpr{IDs: []string{"engineering", "finance"}}}
	credential := contract.RuleExpr{Type: "credential", Credential: &contract.IdentityExpr{IDs: []string{"revoked-device"}}}
	rule := contract.RouteRule{Rules: []contract.RuleExpr{{Type: "all", All: []contract.RuleExpr{user, {Type: "any", Any: []contract.RuleExpr{group}}, {Type: "not", Not: &credential}, {Type: "network", Network: &contract.NetworkExpr{Network: "tcp"}}}}}}
	if err := contract.ValidateConditions(rule.Rules); err != nil {
		t.Fatal(err)
	}
	matcher := ParseMatcher(rule)
	address, _ := netapi.ParseAddress("tcp", "example.com:443")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tt := range []struct {
		name     string
		identity *proxyauth.Identity
		want     bool
	}{
		{"anonymous", nil, false},
		{"incomplete", &proxyauth.Identity{UserID: "alice", Context: t.Context()}, false},
		{"missing-context", &proxyauth.Identity{UserID: "alice", CredentialID: "phone", GroupIDs: []string{"finance"}}, false},
		{"unknown", &proxyauth.Identity{UserID: "other", CredentialID: "phone", Context: t.Context(), GroupIDs: []string{"finance"}}, false},
		{"overlapping", &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context(), GroupIDs: []string{"engineering", "finance"}}, true},
		{"credential-deny", &proxyauth.Identity{UserID: "alice", CredentialID: "revoked-device", Context: t.Context(), GroupIDs: []string{"finance"}}, false},
		{"revoked", &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: canceled, GroupIDs: []string{"finance"}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := netapi.WithContext(netapi.WithTrafficIdentity(t.Context(), tt.identity))
			if got := matcher.Match(ctx, address); got != tt.want {
				t.Fatalf("match=%v, want=%v", got, tt.want)
			}
		})
	}
	template := buildMatchTraceTemplate(matcher)
	if !slices.ContainsFunc(template.Children[0].Children, func(node contractconnection.MatchTraceTemplate) bool {
		return node.Label == "user" && node.EmitsHistory
	}) {
		t.Fatalf("identity trace missing: %+v", template)
	}
}

func BenchmarkIdentityGroupMatch(b *testing.B) {
	for _, size := range []int{1, 64, 1024} {
		for _, memberships := range []int{1, 64} {
			b.Run(fmt.Sprintf("policy=%d/members=%d", size, memberships), func(b *testing.B) {
				ids := make([]string, size)
				for i := range ids {
					ids[i] = fmt.Sprintf("group-%04d", i)
				}
				groups := make([]string, memberships)
				for i := range groups {
					groups[i] = fmt.Sprintf("aaa-%04d", i)
				}
				groups[len(groups)-1] = ids[len(ids)-1]
				matcher := newIdentityMatcher("group", ids)
				ctx := netapi.WithContext(netapi.WithTrafficIdentity(b.Context(), &proxyauth.Identity{UserID: "alice", CredentialID: "phone", GroupIDs: groups, Context: b.Context()}))
				address, _ := netapi.ParseAddress("tcp", "example.com:443")
				b.ReportAllocs()
				for b.Loop() {
					if !matcher.Match(ctx, address) {
						b.Fatal("no match")
					}
				}
			})
		}
	}
}

func BenchmarkIdentityMatch1024ConcurrentUsers(b *testing.B) {
	matcher := newIdentityMatcher("group", []string{"finance"})
	contexts := make([]*netapi.Context, 1024)
	for i := range contexts {
		contexts[i] = netapi.WithContext(netapi.WithTrafficIdentity(b.Context(), &proxyauth.Identity{UserID: fmt.Sprintf("user-%04d", i), CredentialID: fmt.Sprintf("device-%04d", i), GroupIDs: []string{"finance"}, Context: b.Context()}))
	}
	address, _ := netapi.ParseAddress("tcp", "example.com:443")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if !matcher.Match(contexts[i%len(contexts)], address) {
				b.Fatal("no match")
			}
			i++
		}
	})
}
