package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestClientRoundTripV2Wire(t *testing.T) {
	resolver := NewClient(Config{Subnet: netip.MustParsePrefix("192.0.2.0/24")}, TransportFunc(func(_ context.Context, req *Request) (dns.Msg, error) {
		var query dns.Msg
		query.Data = append(query.Data, req.Bytes()...)
		if err := query.Unpack(); err != nil {
			return dns.Msg{}, err
		}
		if query.UDPSize != 8192 || len(query.Pseudo) != 1 {
			return dns.Msg{}, fmt.Errorf("v2 EDNS fields not preserved: udp=%d pseudo=%d", query.UDPSize, len(query.Pseudo))
		}
		if _, ok := query.Pseudo[0].(*dns.SUBNET); !ok {
			return dns.Msg{}, fmt.Errorf("expected SUBNET, got %T", query.Pseudo[0])
		}

		question := query.Question[0]
		response := dns.Msg{
			MsgHeader: dns.MsgHeader{ID: query.ID, Response: true, Rcode: dns.RcodeSuccess},
			Question:  query.Question,
			Answer: []dns.RR{&dns.A{
				Hdr: dns.Header{Name: question.Header().Name, Class: dns.ClassINET, TTL: 60},
				A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
			}},
		}
		if err := response.Pack(); err != nil {
			return dns.Msg{}, err
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
