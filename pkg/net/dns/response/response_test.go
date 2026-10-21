package response

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type upstream struct{ calls atomic.Int64 }

func (u *upstream) Raw(_ context.Context, q netapi.DNSQuestion) (*dns.Msg, error) {
	u.calls.Add(1)
	return netapi.NewDNSMsg(q), nil
}
func (u *upstream) LookupIP(_ context.Context, _ string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	u.calls.Add(1)
	o := &netapi.LookupIPOption{}
	for _, f := range opts {
		f(o)
	}
	ips := &netapi.IPs{}
	if o.Mode != netapi.ResolverModePreferIPv6 {
		ips.A = []net.IP{net.ParseIP("192.0.2.1")}
	}
	if o.Mode != netapi.ResolverModePreferIPv4 {
		ips.AAAA = []net.IP{net.ParseIP("2001:db8::1")}
	}
	return ips, nil
}
func (*upstream) Name() string { return "test" }
func (*upstream) Close() error { return nil }

func TestCustomResponses(t *testing.T) {
	u := &upstream{}
	r := New(u)
	config := contract.ResponseRules{Rules: []contract.ResponseRule{
		{Domain: "*.example.com", QueryType: "HTTPS", Rcode: "NXDOMAIN"},
		{Domain: "*.a.example.com", QueryType: "AAAA", Rcode: "NOERROR", TTL: 123, Answers: []string{"::1", "2001:db8::2"}},
		{Domain: "txt.example", QueryType: "TXT", Rcode: "NOERROR", TTL: 0, Answers: []string{`"custom text"`}},
		{Domain: "empty.example", QueryType: "A", Rcode: "NOERROR"},
		{Domain: "service.example", QueryType: "HTTPS", Rcode: "NOERROR", Answers: []string{`1 . alpn="h2"`}},
	}}
	if err := r.Apply(config); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		typ      uint16
		class    uint16
		code     uint16
		answers  int
		fallback bool
	}{
		{"www.example.com.", dns.TypeHTTPS, dns.ClassINET, dns.RcodeNameError, 0, false},
		{"X.Y.EXAMPLE.COM.", dns.TypeHTTPS, dns.ClassINET, dns.RcodeNameError, 0, false},
		{"example.com.", dns.TypeHTTPS, dns.ClassINET, 0, 0, true},
		{"badexample.com.", dns.TypeHTTPS, dns.ClassINET, 0, 0, true},
		{"www.example.com.", dns.TypeA, dns.ClassINET, 0, 0, true},
		{"x.a.example.com.", dns.TypeAAAA, dns.ClassINET, 0, 2, false},
		{"x.a.example.com.", dns.TypeAAAA, dns.ClassCHAOS, 0, 0, true},
		{"txt.example.", dns.TypeTXT, dns.ClassINET, 0, 1, false},
		{"empty.example.", dns.TypeA, dns.ClassINET, 0, 0, false},
		{"service.example.", dns.TypeHTTPS, dns.ClassINET, 0, 1, false},
	} {
		t.Run(fmt.Sprintf("%s/%d/%d", test.name, test.typ, test.class), func(t *testing.T) {
			before := u.calls.Load()
			q := netapi.DNSQuestion{Name: test.name, Qtype: test.typ, Qclass: test.class}
			msg, err := r.Raw(t.Context(), q)
			if err != nil {
				t.Fatal(err)
			}
			if msg.Rcode != test.code || len(msg.Answer) != test.answers {
				t.Fatalf("response = %v", msg)
			}
			if (u.calls.Load() > before) != test.fallback {
				t.Fatal("unexpected upstream access")
			}
			for _, rr := range msg.Answer {
				if rr.Header().Name != test.name {
					t.Fatal("wrong answer owner")
				}
				if dns.RRToType(rr) != test.typ {
					t.Fatal("answer record type changed")
				}
			}
			if err := msg.Pack(); err != nil {
				t.Fatal(err)
			}
			decoded := &dns.Msg{Data: msg.Data}
			if err := decoded.Unpack(); err != nil {
				t.Fatal(err)
			}
			if len(decoded.Question) != 1 || netapi.DNSQuestionFromRR(decoded.Question[0]) != q {
				t.Fatal("question not preserved")
			}
		})
	}
	q := netapi.DNSQuestion{Name: "x.a.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	msg, _ := r.Raw(t.Context(), q)
	if msg.Answer[0].(*dns.AAAA).Addr != netip.IPv6Loopback() || msg.Answer[0].Header().TTL != 123 {
		t.Fatal("wrong address or TTL")
	}
	msg.Answer[0].(*dns.AAAA).Addr = netip.IPv6Unspecified()
	next, _ := r.Raw(t.Context(), q)
	if next.Answer[0].(*dns.AAAA).Addr != netip.IPv6Loopback() {
		t.Fatal("caller mutated rule snapshot")
	}
	config.Rules[1].Answers[0] = "bad address"
	if err := r.Apply(config); err == nil {
		t.Fatal("accepted invalid update")
	}
	next, _ = r.Raw(t.Context(), q)
	if next.Answer[0].(*dns.AAAA).Addr != netip.IPv6Loopback() {
		t.Fatal("invalid update replaced active rules")
	}
	if err := r.Apply(contract.ResponseRules{}); err != nil {
		t.Fatal(err)
	}
	before := u.calls.Load()
	_, _ = r.Raw(t.Context(), q)
	if u.calls.Load() != before+1 {
		t.Fatal("cleared rule still matched")
	}
}

func BenchmarkResponseRulesApply(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			config := contract.ResponseRules{}
			for i := range count {
				config.Rules = append(config.Rules, contract.ResponseRule{Domain: fmt.Sprintf("*.d%d.example", i), QueryType: "HTTPS", Rcode: "NXDOMAIN"})
			}
			r := New(&upstream{})
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			b.ReportAllocs()
			for b.Loop() {
				if err := r.Apply(config); err != nil {
					b.Fatal(err)
				}
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			if after.HeapAlloc > before.HeapAlloc {
				b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(count), "retained-B/rule")
			}
			runtime.KeepAlive(r)
			runtime.KeepAlive(config)
		})
	}
}

func TestFirstMatchingRuleWins(t *testing.T) {
	for _, rules := range [][]contract.ResponseRule{
		{{Domain: "*.example.com", QueryType: "*", Rcode: "REFUSED"}, {Domain: "x.example.com", QueryType: "A", Rcode: "NXDOMAIN"}},
		{{Domain: "x.example.com", QueryType: "A", Rcode: "REFUSED"}, {Domain: "*.example.com", QueryType: "*", Rcode: "NXDOMAIN"}},
		{{Domain: "*", QueryType: "A", Rcode: "REFUSED"}, {Domain: "x.example.com", QueryType: "A", Rcode: "NXDOMAIN"}},
		{{Domain: "*.example.com", QueryType: "A", Rcode: "REFUSED"}, {Domain: "*.example.com", QueryType: "A", Rcode: "NXDOMAIN"}},
	} {
		r := New(&upstream{})
		if err := r.Apply(contract.ResponseRules{Rules: rules}); err != nil {
			t.Fatal(err)
		}
		msg, err := r.Raw(t.Context(), netapi.DNSQuestion{Name: "x.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		if err != nil || msg.Rcode != dns.RcodeRefused {
			t.Fatalf("first match = %v, %v", msg, err)
		}
	}
}

func TestLookupIPHonorsRulesAndFamily(t *testing.T) {
	u := &upstream{}
	r := New(u)
	config := contract.ResponseRules{Rules: []contract.ResponseRule{{Domain: "example.com", QueryType: "AAAA", Rcode: "NOERROR", Answers: []string{"::1"}}}}
	if err := r.Apply(config); err != nil {
		t.Fatal(err)
	}
	ips, err := r.LookupIP(t.Context(), "example.com")
	if err != nil || len(ips.A) != 1 || len(ips.AAAA) != 1 || !ips.AAAA[0].Equal(net.IPv6loopback) {
		t.Fatalf("lookup = %+v, %v", ips, err)
	}
	before := u.calls.Load()
	ips, err = r.LookupIP(t.Context(), "example.com.", func(o *netapi.LookupIPOption) { o.Mode = netapi.ResolverModePreferIPv6 })
	if err != nil || len(ips.A) != 0 || !ips.AAAA[0].Equal(net.IPv6loopback) || u.calls.Load() != before {
		t.Fatal("IPv6-only lookup queried upstream")
	}
	config.Rules[0].QueryType, config.Rules[0].Rcode, config.Rules[0].Answers = "*", "NXDOMAIN", nil
	if err := r.Apply(config); err != nil {
		t.Fatal(err)
	}
	_, err = r.LookupIP(t.Context(), "example.com")
	if e, ok := errors.AsType[*net.DNSError](err); !ok || !e.IsNotFound {
		t.Fatalf("blocked lookup error = %v", err)
	}
	if u.calls.Load() != before {
		t.Fatal("blocked lookup queried upstream")
	}
}

func TestConcurrentQueriesAndUpdates(t *testing.T) {
	r := New(&upstream{})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 100 {
				if i == 0 {
					if err := r.Apply(contract.ResponseRules{Rules: []contract.ResponseRule{{Domain: "*.example.com", QueryType: "A", Rcode: "NXDOMAIN"}}}); err != nil {
						t.Error(err)
					}
				} else {
					_, err := r.Raw(t.Context(), netapi.DNSQuestion{Name: "x.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
					if err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkResponseRules(b *testing.B) {
	for _, count := range []int{10, 1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			r := New(&upstream{})
			config := contract.ResponseRules{}
			for i := range count {
				config.Rules = append(config.Rules, contract.ResponseRule{Domain: fmt.Sprintf("*.d%d.example", i), QueryType: "HTTPS", Rcode: "NXDOMAIN"})
			}
			if err := r.Apply(config); err != nil {
				b.Fatal(err)
			}
			q := netapi.DNSQuestion{Name: fmt.Sprintf("x.d%d.example.", count-1), Qtype: dns.TypeHTTPS, Qclass: dns.ClassINET}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := r.Raw(b.Context(), q); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
