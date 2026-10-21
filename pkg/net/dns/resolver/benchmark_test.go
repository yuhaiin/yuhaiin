package resolver

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func cachedBenchmarkClient(tb testing.TB) (netapi.Resolver, netapi.DNSQuestion) {
	tb.Helper()
	r := NewClient(Config{Name: "benchmark"}, TransportFunc(func(_ context.Context, req *Request) (*dns.Msg, error) {
		msg := netapi.NewDNSMsg(req.Question)
		msg.ID = req.ID
		msg.Answer = []dns.RR{&dns.A{Hdr: dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 600}, Addr: netip.MustParseAddr("192.0.2.1")}}
		if err := msg.Pack(); err != nil {
			return nil, err
		}
		return msg, nil
	}))
	tb.Cleanup(func() { _ = r.Close() })
	q := netapi.DNSQuestion{Name: "cache.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if _, err := r.Raw(tb.Context(), q); err != nil {
		tb.Fatal(err)
	}
	return r, q
}

func BenchmarkClientRawCached(b *testing.B) {
	r, q := cachedBenchmarkClient(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := r.Raw(b.Context(), q); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDNSCacheKeys(b *testing.B) {
	q := netapi.DNSQuestion{Name: "cache.example.", Qtype: dns.TypeHTTPS, Qclass: dns.ClassINET}
	b.Run("client", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if CacheKeyFromQuestion(q) == "" {
				b.Fatal("empty key")
			}
		}
	})
	b.Run("udp", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if udpCacheKey(12345, q) == "" {
				b.Fatal("empty key")
			}
		}
	})
}

func TestCachedRawResponsesCanBePackedConcurrently(t *testing.T) {
	r, q := cachedBenchmarkClient(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 30 {
				msg, err := r.Raw(t.Context(), q)
				if err != nil {
					t.Error(err)
					return
				}
				msg.ID = uint16(i)
				if err := msg.Pack(); err != nil {
					t.Error(err)
				}
				decoded := &dns.Msg{Data: msg.Data}
				if err := decoded.Unpack(); err != nil || decoded.ID != uint16(i) {
					t.Errorf("response ID = %d, want %d, error %v", decoded.ID, i, err)
				}
			}
		})
	}
	wg.Wait()
}
