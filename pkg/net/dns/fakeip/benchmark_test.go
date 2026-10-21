package fakeip

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// Seed in one transaction so benchmark setup does not measure thousands of
// individual durable commits. Timed operations still use the production pool.
func benchmarkFakeIPPool(b *testing.B, size, capacity int) (*SQLiteFakeIPPool, []string, []netip.Addr) {
	b.Helper()
	p, db := newTestSQLiteFakeIPPool(b, netip.MustParsePrefix("198.18.0.0/15"), capacity)
	tx, err := db.BeginTx(b.Context(), nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	domains := make([]string, size)
	ips := make([]netip.Addr, size)
	now := time.Now()
	for i := range size {
		domains[i] = fmt.Sprintf("domain-%d.example", i)
		ips[i] = p.rotateNext()
		if err := p.storeEntry(b.Context(), tx, domains[i], ips[i], now); err != nil {
			b.Fatal(err)
		}
	}
	if err := p.saveCursor(b.Context(), tx, now); err != nil {
		b.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return p, domains, ips
}

func BenchmarkFakeIPHotPath(b *testing.B) {
	for _, operation := range []string{"domain", "reverse", "lease_release", "parallel_domain", "parallel_lease_release"} {
		b.Run(operation, func(b *testing.B) {
			p, domains, ips := benchmarkFakeIPPool(b, 4096, 65535)
			for i, domain := range domains {
				if got := p.GetFakeIPForDomain(domain); got != ips[i] {
					b.Fatal("cannot warm mapping fixture")
				}
			}
			run := func(i int) {
				switch operation {
				case "domain", "parallel_domain":
					if got := p.GetFakeIPForDomain(domains[i]); got != ips[i] {
						b.Fatal("domain mapping changed")
					}
				case "reverse":
					if got, ok := p.GetDomainFromIP(ips[i]); !ok || got != domains[i] {
						b.Fatal("reverse mapping changed")
					}
				default:
					got, release, ok := p.LeaseDomainFromIP(ips[i])
					if !ok || got != domains[i] {
						b.Fatal("lease mapping changed")
					}
					release()
				}
			}
			b.ReportAllocs()
			if operation == "parallel_domain" || operation == "parallel_lease_release" {
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					i := 0
					for pb.Next() {
						run(i % len(domains))
						i++
					}
				})
				return
			}
			for i := 0; b.Loop(); i++ {
				run(i % len(domains))
			}
		})
	}
}

// A cyclic working set four times larger than the cache deliberately misses
// every cache lookup, exposing the overhead of the bounded-cache fallback.
func BenchmarkFakeIPCacheChurn(b *testing.B) {
	p, domains, ips := benchmarkFakeIPPool(b, 16384, 65535)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		index := i % len(domains)
		if got := p.GetFakeIPForDomain(domains[index]); got != ips[index] {
			b.Fatal("cold mapping changed")
		}
	}
}

// Run with -benchtime=500x so every timed operation remains a new allocation
// rather than eventually measuring pool exhaustion as successful throughput.
func BenchmarkFakeIPNewDomain(b *testing.B) {
	for _, seeded := range []int{0, 4096, 49152} {
		b.Run(fmt.Sprint(seeded), func(b *testing.B) {
			p, _, _ := benchmarkFakeIPPool(b, seeded, 65535)
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				if !p.GetFakeIPForDomain(fmt.Sprintf("new-%d.example", i)).IsValid() {
					b.Fatal("pool exhausted; run with -benchtime=500x")
				}
			}
		})
	}
}

func BenchmarkFakeIPExhausted(b *testing.B) {
	for _, leased := range []bool{false, true} {
		b.Run(fmt.Sprintf("leased_%t", leased), func(b *testing.B) {
			p, _, ips := benchmarkFakeIPPool(b, 4096, 4096)
			if leased {
				for _, ip := range ips {
					_, release, ok := p.LeaseDomainFromIP(ip)
					if !ok {
						b.Fatal("cannot lease fixture")
					}
					b.Cleanup(release)
				}
				if err := p.flushTouches(b.Context()); err != nil {
					b.Fatal(err)
				}
				if _, err := p.db.ExecContext(b.Context(), `UPDATE fakeip_entries SET last_used_at = ?`, time.Now().Add(-2*time.Hour).UnixNano()); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				if p.GetFakeIPForDomain("unavailable.example").IsValid() {
					b.Fatal("protected mapping was evicted")
				}
			}
		})
	}
}

type benchmarkHTTPSResolver struct {
	netapi.Resolver
	message *dns.Msg
}

func (r benchmarkHTTPSResolver) Raw(context.Context, netapi.DNSQuestion) (*dns.Msg, error) {
	return r.message, nil
}

func BenchmarkFakeIPHTTPS(b *testing.B) {
	p, domains, _ := benchmarkFakeIPPool(b, 1, 65535)
	p6, err := newSQLiteFakeIPPool(p.db, netip.MustParsePrefix("2001:2::/64"), 65535)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = p6.Close() })
	if !p6.GetFakeIPForDomain(domains[0]).IsValid() {
		b.Fatal("cannot allocate IPv6 fixture")
	}
	service := &dns.HTTPS{}
	service.Hdr = dns.Header{Name: domains[0] + ".", Class: dns.ClassINET, TTL: 60}
	service.Priority, service.Target = 1, "."
	service.Value = []svcb.Pair{&svcb.ALPN{Alpn: []string{"h2", "h3"}}, &svcb.IPV4HINT{Hint: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}}
	f := &FakeDNS{Resolver: benchmarkHTTPSResolver{message: &dns.Msg{Answer: []dns.RR{service}}}, ipv4: p, ipv6: p6}
	question := netapi.DNSQuestion{Name: service.Hdr.Name, Qtype: dns.TypeHTTPS, Qclass: dns.ClassINET}
	b.ReportAllocs()
	for b.Loop() {
		msg, err := f.Raw(b.Context(), question)
		if err != nil || msg == nil || len(msg.Answer) != 1 {
			b.Fatal("HTTPS rewrite failed", err)
		}
	}
}
