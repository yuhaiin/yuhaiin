package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

func TestClientRoundTripV2Wire(t *testing.T) {
	resolver := NewClient(Config{Subnet: netip.MustParsePrefix("192.0.2.0/24")}, TransportFunc(func(_ context.Context, req *Request) (*dns.Msg, error) {
		var query dns.Msg
		query.Data = append(query.Data, req.Bytes()...)
		if err := query.Unpack(); err != nil {
			return nil, err
		}
		if query.UDPSize != 8192 || len(query.Pseudo) != 1 {
			return nil, fmt.Errorf("v2 EDNS fields not preserved: udp=%d pseudo=%d", query.UDPSize, len(query.Pseudo))
		}
		if _, ok := query.Pseudo[0].(*dns.SUBNET); !ok {
			return nil, fmt.Errorf("expected SUBNET, got %T", query.Pseudo[0])
		}

		question := query.Question[0]
		response := &dns.Msg{
			ID: query.ID, Response: true, Rcode: dns.RcodeSuccess,
			Question: query.Question,
			Answer: []dns.RR{&dns.A{
				Hdr:  dns.Header{Name: question.Header().Name, Class: dns.ClassINET, TTL: 60},
				Addr: netip.MustParseAddr("192.0.2.1"),
			}},
		}
		if err := response.Pack(); err != nil {
			return nil, err
		}
		return response, nil
	}))

	ips, err := resolver.LookupIP(context.Background(), "example.com", func(opt *netapi.LookupIPOption) {
		opt.Mode = netapi.ResolverModePreferIPv4
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := net.ParseIP("192.0.2.1").String(); len(ips.A) != 1 || ips.A[0].String() != want {
		t.Fatalf("resolved addresses = %v, want %s", ips.A, want)
	}
}

func ExampleNew() {
	subnet, err := netip.ParsePrefix("1.1.1.1/24")
	if err != nil {
		panic(err)
	}

	r, err := New(Config{
		Type:       "doh",
		Name:       "cloudflare",
		Host:       "cloudflare-dns.com",
		Servername: "cloudflare-dns.com",
		Subnet:     subnet,
	})
	if err != nil {
		panic(err)
	}
	defer r.Close()

	msg, err := r.Raw(context.Background(), netapi.DNSQuestion{})
	if err != nil {
		panic(err)
	}

	fmt.Println(msg)
}

func TestClientDNSCacheSnapshotAndClear(t *testing.T) {
	client := NewClient(Config{Name: "test"}, TransportFunc(func(context.Context, *Request) (*dns.Msg, error) {
		return nil, fmt.Errorf("unexpected network request")
	})).(*client)

	response := func(name string, rr dns.RR) *dns.Msg {
		return &dns.Msg{Rcode: dns.RcodeSuccess, Answer: []dns.RR{rr}, Question: []dns.RR{netapi.DNSQuestion{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}.RR()}}
	}
	client.rawStore.Add("Example.COM.:1", response("Example.COM.", &dns.A{Hdr: dns.Header{Name: "Example.COM.", Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr("192.0.2.1")}), lru.WithTimeout[string, *dns.Msg](time.Minute))
	client.rawStore.Add("example.com:28", response("example.com", &dns.AAAA{Hdr: dns.Header{Name: "example.com", Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr("2001:db8::1")}), lru.WithTimeout[string, *dns.Msg](time.Minute))
	client.iphintToCache("EXAMPLE.COM.", 60, &svcb.IPV4HINT{Hint: []netip.Addr{netip.MustParseAddr("192.0.2.2")}})
	client.rawStore.Add("other.example:1", response("other.example", &dns.A{Hdr: dns.Header{Name: "other.example", Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr("192.0.2.4")}), lru.WithTimeout[string, *dns.Msg](time.Minute))
	client.rawStore.Add("expired.example:1", response("expired.example", &dns.A{Hdr: dns.Header{Name: "expired.example", Class: dns.ClassINET}, Addr: netip.MustParseAddr("192.0.2.3")}), lru.WithTimeout[string, *dns.Msg](time.Nanosecond))
	time.Sleep(2 * time.Millisecond)

	entries := client.DNSCacheEntries()
	if len(entries) != 4 {
		t.Fatalf("snapshot entries=%d, want 4 valid entries", len(entries))
	}
	for _, entry := range entries {
		if entry.Question.Name == "expired.example" {
			t.Fatal("expired entry was included in snapshot")
		}
		if entry.ExpiresIn <= 0 {
			t.Fatalf("entry %q has invalid expiration %s", entry.Question.Name, entry.ExpiresIn)
		}
	}

	if removed := client.ClearDNSCache("eXaMpLe.CoM."); removed != 3 {
		t.Fatalf("removed=%d, want all A, AAAA and HTTPS hint entries", removed)
	}
	if _, ok := client.rawStore.Load("expired.example:1"); ok {
		t.Fatal("clearing example.com removed or retained wrong entry")
	}
	if _, ok := client.rawStore.Load("other.example:1"); !ok {
		t.Fatal("clearing example.com removed an unrelated domain")
	}
	if client.rawStore.Len() != 1 {
		t.Fatalf("cache length=%d, want unrelated entry to remain", client.rawStore.Len())
	}
}
