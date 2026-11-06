package resolver

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	dnsresolver "github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/response"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestCachedDNSFollowsRouteHostsAndFakeIP(t *testing.T) {
	oldDir := configuration.DataDir.Load()
	dataDir := t.TempDir()
	configuration.DataDir.Store(dataDir)
	t.Cleanup(func() { configuration.DataDir.Store(oldDir) })
	db, err := sqlite.Open(t.Context(), filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	settings := store.NewRouteSettingsStore(db.DB())
	routingSettings := store.RouteSettings{DefaultMode: "direct", DirectResolver: "left", ProxyResolver: "right"}
	if err := settings.SaveSettings(t.Context(), routingSettings); err != nil {
		t.Fatal(err)
	}
	resolvers := NewResolver(direct.Default)
	t.Cleanup(func() { _ = resolvers.Close() })
	var calls atomic.Int32
	for _, entry := range []struct{ name, ip string }{{"left", "192.0.2.1"}, {"right", "192.0.2.2"}} {
		ip := netip.MustParseAddr(entry.ip)
		upstream := dnsresolver.NewClient(dnsresolver.Config{Name: entry.name}, dnsresolver.TransportFunc(func(_ context.Context, req *dnsresolver.Request) (*dns.Msg, error) {
			calls.Add(1)
			if req.Question.Qtype == dns.TypeAAAA {
				return &dns.Msg{ID: req.ID, Response: true, Answer: []dns.RR{&dns.AAAA{Hdr: dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 600}, Addr: netip.MustParseAddr("2001:db8::1")}}}, nil
			}
			return &dns.Msg{ID: req.ID, Response: true, Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 600}, Addr: ip}}}, nil
		}))
		resolvers.store.Store(entry.name, &Entry{Resolver: upstream})
	}
	lists := route.NewLists(store.NewRouteListStore(db.DB()), settings, dataDir)
	t.Cleanup(func() { _ = lists.Close() })
	router := route.NewRoute(nil, resolvers, lists, nil)
	routing := route.NewRules(store.NewRouteRuleStore(db.DB()), settings, router)
	t.Cleanup(func() { _ = routing.Close() })
	if err := routing.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	hosts := NewHosts(nil, router)
	hosts.Apply(map[string]string{"hosts.example": "203.0.113.7"})
	fake, err := NewFakeDNS(nil, hosts, filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fake.Close() })
	if err := fake.Apply(contract.FakeDNS{SkipCheckList: []string{"synthetic.example"}, Whitelist: []string{"plain.example"}}); err != nil {
		t.Fatal(err)
	}
	root := response.New(fake)
	if err := root.Apply(contract.ResponseRules{Rules: []contract.ResponseRule{{Domain: "local.example", QueryType: "A", Rcode: "NOERROR", TTL: 60, Answers: []string{"203.0.113.8"}}}}); err != nil {
		t.Fatal(err)
	}
	query := func(name string) netapi.DNSQuestion {
		return netapi.DNSQuestion{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	}
	check := func(name, want string, forceFake bool) {
		t.Helper()
		ctx := netapi.WithContext(t.Context())
		ctx.ConnOptions().Resolver().SetUseFakeIP(forceFake)
		before := calls.Load()
		msg, err := netapi.CachedDNS(ctx, root, query(name))
		if err != nil || len(msg.Answer) != 1 {
			t.Fatalf("cached %s: %v %v", name, msg, err)
		}
		got := msg.Answer[0].(*dns.A).Addr
		if want == "fake" {
			if !fake.FakeIPRanges()[0].Contains(got) {
				t.Fatalf("lost forced FakeIP: %s", got)
			}
		} else if got.String() != want {
			t.Fatalf("cached %s=%s want %s", name, got, want)
		}
		if calls.Load() != before {
			t.Fatal("cache-only lookup queried upstream")
		}
	}
	q := query("plain.example.")
	if _, err := router.RawCached(netapi.WithContext(t.Context()), q); !errors.Is(err, netapi.ErrDNSCacheMiss) {
		t.Fatalf("direct cache probe=%v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("direct routed cache probe performed I/O")
	}
	if _, err := netapi.CachedDNS(netapi.WithContext(t.Context()), root, q); !errors.Is(err, netapi.ErrDNSCacheMiss) {
		t.Fatalf("cold lookup=%v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("cold cache probe performed network I/O")
	}
	if _, err := root.Raw(netapi.WithContext(t.Context()), q); err != nil {
		t.Fatal(err)
	}
	check(q.Name, "192.0.2.1", false)
	routingSettings.DefaultMode = "proxy"
	if err := settings.SaveSettings(t.Context(), routingSettings); err != nil {
		t.Fatal(err)
	}
	if err := routing.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Routing's IP-list lookup has already warmed the proxy resolver. The cache
	// fast path must follow the new mode instead of borrowing the direct answer.
	check(q.Name, "192.0.2.2", false)
	if _, err := root.Raw(netapi.WithContext(t.Context()), q); err != nil {
		t.Fatal(err)
	}
	check(q.Name, "192.0.2.2", false)
	check("hosts.example.", "203.0.113.7", false)
	check("local.example.", "203.0.113.8", true)
	check("synthetic.example.", "fake", true)
	check("plain.example.", "192.0.2.2", true)
}
