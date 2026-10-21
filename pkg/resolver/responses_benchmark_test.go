package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	dnsresolver "github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/response"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

// These fixtures use the real Hosts, FakeIP, cache and DNS server. The upstream
// transport is deterministic and local; external network latency is excluded.
func benchmarkDNSPipeline(b *testing.B, kind string, count int, wrap bool) (netapi.Resolver, []byte) {
	b.Helper()
	upstream := dnsresolver.NewClient(dnsresolver.Config{Name: "pipeline-benchmark"}, dnsresolver.TransportFunc(func(_ context.Context, req *dnsresolver.Request) (*dns.Msg, error) {
		msg := netapi.NewDNSMsg(req.Question)
		msg.ID = req.ID
		msg.Answer = []dns.RR{&dns.A{Hdr: dns.Header{Name: req.Question.Name, TTL: 600, Class: dns.ClassINET}, Addr: netip.MustParseAddr("192.0.2.1")}}
		if err := msg.Pack(); err != nil {
			return nil, err
		}
		return msg, nil
	}))
	b.Cleanup(func() { _ = upstream.Close() })
	hosts := NewHosts(nil, upstream)
	hosts.Apply(map[string]string{"hosts.example": "127.0.0.1"})
	fake, err := NewFakeDNS(nil, hosts, filepath.Join(b.TempDir(), "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = fake.Close() })
	if err := fake.Apply(contract.FakeDNS{Enabled: kind == "fakeip", SkipCheckList: []string{"*"}}); err != nil {
		b.Fatal(err)
	}
	var root netapi.Resolver = fake
	rules := response.New(fake)
	config := contract.ResponseRules{}
	for i := range count {
		config.Rules = append(config.Rules, contract.ResponseRule{Domain: fmt.Sprintf("*.d%d.example", i), QueryType: "HTTPS", Rcode: "NXDOMAIN"})
	}
	q := netapi.DNSQuestion{Name: "cache.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	switch kind {
	case "nxdomain":
		q.Name, q.Qtype = fmt.Sprintf("x.d%d.example.", count-1), dns.TypeHTTPS
	case "aaaa":
		q.Name, q.Qtype = "x.a.example.com.", dns.TypeAAAA
		config.Rules = append(config.Rules, contract.ResponseRule{Domain: "*.a.example.com", QueryType: "AAAA", Rcode: "NOERROR", TTL: 300, Answers: []string{"::1"}})
	case "hosts":
		q.Name = "hosts.example."
	}
	if err := rules.Apply(config); err != nil {
		b.Fatal(err)
	}
	if wrap {
		root = rules
	}
	if _, err := root.Raw(netapi.WithContext(b.Context()), q); err != nil {
		b.Fatal(err)
	}
	query := netapi.NewDNSMsg(q)
	query.Response, query.ID = false, 42
	if err := query.Pack(); err != nil {
		b.Fatal(err)
	}
	return root, query.Data
}

func BenchmarkDNSDatagramPipeline(b *testing.B) {
	for _, test := range []struct {
		kind  string
		count int
		wrap  bool
	}{
		{"cache", 0, false}, {"cache", 0, true}, {"cache", 10000, true},
		{"nxdomain", 10, true}, {"nxdomain", 1000, true}, {"nxdomain", 10000, true},
		{"aaaa", 10000, true}, {"hosts", 10000, true}, {"fakeip", 10000, true},
	} {
		b.Run(fmt.Sprintf("%s/rules=%d/wrap=%t", test.kind, test.count, test.wrap), func(b *testing.B) {
			root, query := benchmarkDNSPipeline(b, test.kind, test.count, test.wrap)
			agent := NewDNSServer(root)
			b.Cleanup(func() { _ = agent.Close() })
			done := make(chan int, 1)
			write := func(data []byte) error { done <- len(data); return nil }
			b.ReportAllocs()
			for b.Loop() {
				packet := netapi.NewPacket(nil, nil, pool.Clone(query), nil)
				err := agent.DoDatagram(b.Context(), &netapi.DNSRawRequest{Question: packet, WriteBack: write})
				packet.DecRef()
				if err != nil {
					b.Fatal(err)
				}
				if n := <-done; n < 12 {
					b.Fatal("invalid response")
				}
			}
		})
	}
}

func BenchmarkDNSUDPPipeline(b *testing.B) {
	for _, kind := range []string{"cache", "nxdomain", "aaaa", "hosts", "fakeip"} {
		b.Run(kind, func(b *testing.B) {
			root, query := benchmarkDNSPipeline(b, kind, 10000, true)
			agent := server.NewServer("", root)
			b.Cleanup(func() { _ = agent.Close() })
			listener, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			finished := make(chan struct{})
			b.Cleanup(func() { _ = listener.Close(); <-finished })
			handler := agent.(interface {
				HandleUDP(context.Context, net.PacketConn) error
			})
			go func() {
				defer close(finished)
				for {
					if err := handler.HandleUDP(b.Context(), listener); err != nil {
						return
					}
				}
			}()
			client, err := net.Dial("udp", listener.LocalAddr().String())
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = client.Close() })
			_ = client.SetDeadline(time.Now().Add(10 * time.Minute))
			buf := make([]byte, 4096)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := client.Write(query); err != nil {
					b.Fatal(err)
				}
				if n, err := client.Read(buf); err != nil || n < 12 {
					b.Fatalf("DNS response: %d bytes, %v", n, err)
				}
			}
		})
	}
}
