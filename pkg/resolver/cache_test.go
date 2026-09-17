package resolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type cacheResolverStub struct {
	entries []netapi.DNSCacheEntry
}

func (cacheResolverStub) LookupIP(context.Context, string, ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return &netapi.IPs{}, nil
}
func (cacheResolverStub) Raw(context.Context, netapi.DNSQuestion) (*dns.Msg, error) {
	return &dns.Msg{}, nil
}
func (cacheResolverStub) Close() error                              { return nil }
func (cacheResolverStub) Name() string                              { return "stub" }
func (s cacheResolverStub) DNSCacheEntries() []netapi.DNSCacheEntry { return s.entries }
func (cacheResolverStub) ClearDNSCache(string) int                  { return 0 }

func TestDNSCacheOnlyIncludesInstantiatedResolvers(t *testing.T) {
	manager := NewResolver(nil)
	manager.store.Store("active", &Entry{
		Resolver: cacheResolverStub{entries: []netapi.DNSCacheEntry{{
			Question: netapi.DNSQuestion{Name: "active.example.", Qtype: dns.TypeA},
			Message: &dns.Msg{
				Rcode:  dns.RcodeSuccess,
				Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: "active.example.", Class: dns.ClassINET}, Addr: netip.MustParseAddr("192.0.2.1")}},
				Ns:     []dns.RR{&dns.A{Hdr: dns.Header{Name: "active.example.", Class: dns.ClassINET}, Addr: netip.MustParseAddr("192.0.2.2")}},
				Extra:  []dns.RR{&dns.A{Hdr: dns.Header{Name: "active.example.", Class: dns.ClassINET}, Addr: netip.MustParseAddr("192.0.2.3")}},
			},
			ExpiresIn: time.Minute,
		}}},
		Config: contractresolver.Resolver{ID: "active"},
	})
	manager.resolvers.Store("configured", contractresolver.Resolver{ID: "configured", Type: "udp", Host: "192.0.2.1:53"})

	items := manager.DNSCache().Items
	var foundActive bool
	for _, item := range items {
		if item.Resolver == "active" {
			foundActive = true
			if item.ExpiresIn != 60 || len(item.Records) != 3 {
				t.Fatalf("active cache item=%+v, want 60s and all three DNS sections", item)
			}
		}
		if item.Resolver == "configured" {
			t.Fatal("cache inspection instantiated a configured resolver")
		}
	}
	if !foundActive {
		t.Fatal("active resolver cache was not included")
	}
	if _, ok := manager.store.Load("configured"); ok {
		t.Fatal("configured resolver was lazily created")
	}
}

func TestContractDNSCacheClearValidation(t *testing.T) {
	controller := NewContractController(&ResolverCtr{r: NewResolver(nil)})

	if _, err := controller.ClearCache(context.Background(), "active", "not a domain"); err == nil {
		t.Fatal("invalid domain was accepted")
	}
	if _, err := controller.ClearCache(context.Background(), "missing", "example.com."); !errors.Is(err, contractresolver.ErrDNSCacheNotFound) {
		t.Fatalf("missing resolver error=%v, want ErrDNSCacheNotFound", err)
	}
}
