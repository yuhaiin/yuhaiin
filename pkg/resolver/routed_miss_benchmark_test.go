package resolver

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	routecontract "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	dnsresolver "github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/response"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

// benchmarkRoutedDNS builds response → FakeIP → Hosts → Route with ruleCount
// host-list rules that never match, so every route decision evaluates them all.
// A/AAAA answers are cacheable (routing evidence); other types use TTL 0, so a
// TXT query completes routing from cache but always misses its own answer.
func benchmarkRoutedDNS(b *testing.B, ruleCount int) netapi.Resolver {
	b.Helper()
	oldDir := configuration.DataDir.Load()
	dataDir := b.TempDir()
	configuration.DataDir.Store(dataDir)
	b.Cleanup(func() { configuration.DataDir.Store(oldDir) })
	db, err := sqlite.Open(b.Context(), filepath.Join(dataDir, "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	settings := store.NewRouteSettingsStore(db.DB())
	if err := settings.SaveSettings(b.Context(), store.RouteSettings{DefaultMode: "direct", DirectResolver: "up", ProxyResolver: "up"}); err != nil {
		b.Fatal(err)
	}
	resolvers := NewResolver(direct.Default)
	b.Cleanup(func() { _ = resolvers.Close() })
	var calls atomic.Int64
	upstream := dnsresolver.NewClient(dnsresolver.Config{Name: "up"}, dnsresolver.TransportFunc(func(_ context.Context, req *dnsresolver.Request) (*dns.Msg, error) {
		calls.Add(1)
		msg := &dns.Msg{ID: req.ID, Response: true}
		hdr := dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 600}
		switch req.Question.Qtype {
		case dns.TypeA:
			msg.Answer = []dns.RR{&dns.A{Hdr: hdr, Addr: netip.MustParseAddr("192.0.2.1")}}
		case dns.TypeAAAA:
			msg.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, Addr: netip.MustParseAddr("2001:db8::1")}}
		default:
			hdr.TTL = 0
			msg.Answer = []dns.RR{&dns.A{Hdr: hdr, Addr: netip.MustParseAddr("192.0.2.1")}}
		}
		return msg, nil
	}))
	resolvers.store.Store("up", &Entry{Resolver: upstream})
	lists := route.NewLists(store.NewRouteListStore(db.DB()), settings, dataDir)
	b.Cleanup(func() { _ = lists.Close() })
	router := route.NewRoute(nil, resolvers, lists, nil)
	routing := route.NewRules(store.NewRouteRuleStore(db.DB()), settings, router)
	b.Cleanup(func() { _ = routing.Close() })
	editor := store.NewRouteEditorStore(db.DB())
	for i := range ruleCount {
		id := fmt.Sprintf("r%d", i)
		if _, err := editor.Save(b.Context(), routecontract.RuleDraft{
			Rule:  routecontract.RouteRule{ID: id, Name: id, Mode: "direct", Rules: []routecontract.RuleExpr{{Type: "host", Host: &routecontract.ListRef{List: id}}}},
			Lists: []routecontract.RouteListDetail{{ID: id, Name: id, Type: "host", Source: routecontract.ListSource{Type: "local", Local: &routecontract.LocalSource{Lists: []string{fmt.Sprintf("never%d.invalid", i)}}}}},
		}); err != nil {
			b.Fatal(err)
		}
	}
	if err := routing.Apply(b.Context()); err != nil {
		b.Fatal(err)
	}
	hosts := NewHosts(nil, router)
	fake, err := NewFakeDNS(nil, hosts, filepath.Join(dataDir, "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = fake.Close() })
	if err := fake.Apply(contract.FakeDNS{}); err != nil {
		b.Fatal(err)
	}
	return response.New(fake)
}

func packDNSQuery(b *testing.B, name string, qtype uint16) []byte {
	query := netapi.NewDNSMsg(netapi.DNSQuestion{Name: name, Qtype: qtype, Qclass: dns.ClassINET})
	query.Response, query.ID = false, 42
	if err := query.Pack(); err != nil {
		b.Fatal(err)
	}
	return query.Data
}

// BenchmarkDNSRoutedMiss submits uncached questions through the DNS server and
// the routed resolver pipeline. "evidence-cached" has the routing addresses
// cached (TXT answer missing); "cold" uses a new name each time, so routing
// itself needs upstream addresses.
func BenchmarkDNSRoutedMiss(b *testing.B) {
	for _, rules := range []int{10, 200} {
		for _, kind := range []string{"evidence-cached", "cold"} {
			b.Run(fmt.Sprintf("%s/rules=%d", kind, rules), func(b *testing.B) {
				root := benchmarkRoutedDNS(b, rules)
				agent := NewDNSServer(root)
				b.Cleanup(func() { _ = agent.Close() })
				warm := packDNSQuery(b, "routed.example.", dns.TypeTXT)
				if _, err := root.Raw(netapi.WithContext(b.Context()), netapi.DNSQuestion{Name: "routed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}); err != nil {
					b.Fatal(err)
				}
				done := make(chan error, 1)
				write := func([]byte) error { return nil }
				complete := func(err error) { done <- err }
				i := 0
				b.ReportAllocs()
				for b.Loop() {
					query := warm
					if kind == "cold" {
						i++
						query = packDNSQuery(b, fmt.Sprintf("n%d.cold.example.", i), dns.TypeA)
					}
					packet := netapi.NewPacket(nil, nil, pool.Clone(query), nil)
					err := agent.DoDatagram(b.Context(), &netapi.DNSRawRequest{Question: packet, WriteBack: write, Done: complete})
					packet.DecRef()
					if err != nil {
						b.Fatal(err)
					}
					if err := <-done; err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
