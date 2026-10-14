package resolver

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

func TestQueryTypesUseDNSRegistry(t *testing.T) {
	types := QueryTypes().Types
	for code, name := range dns.TypeToString {
		if code == dns.TypeOPT || code == dns.TypeTSIG || code == dns.TypeAXFR || code == dns.TypeIXFR {
			continue
		}
		if !slices.Contains(types, name) {
			t.Fatalf("DNS registry type %s missing", name)
		}
	}
	if slices.Contains(types, "OPT") || slices.Contains(types, "TSIG") || slices.Contains(types, "AXFR") || slices.Contains(types, "IXFR") {
		t.Fatal("message metadata or zone transfers offered as query types")
	}
}

func TestResolverProbeUsesDraftAndBypassesCache(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var received atomic.Int32
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			size, addr, err := socket.ReadFrom(buffer)
			if err != nil {
				return
			}
			query := &dns.Msg{Data: append([]byte{}, buffer[:size]...)}
			if err := query.Unpack(); err != nil {
				t.Error(err)
				return
			}
			received.Add(1)
			question := netapi.DNSQuestionFromRR(query.Question[0])
			reply := &dns.Msg{ID: query.ID, Response: true, RecursionAvailable: true, Question: query.Question}
			header := dns.Header{Name: question.Name, Class: dns.ClassINET, TTL: 60}
			if question.Qtype == dns.TypeTXT {
				reply.Answer = []dns.RR{&dns.TXT{Hdr: header, Txt: []string{"wire-test"}}}
			} else {
				reply.Answer = []dns.RR{&dns.A{Hdr: header, Addr: netip.MustParseAddr("192.0.2.1")}}
			}
			if err := reply.Pack(); err != nil {
				t.Error(err)
				return
			}
			if _, err := socket.WriteTo(reply.Data, addr); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	t.Cleanup(func() { _ = socket.Close(); <-done })
	manager := NewResolver(direct.Default)
	ctr := NewContractController(&ResolverCtr{r: manager})
	request := contractresolver.TestRequest{Resolver: contractresolver.Resolver{ID: "draft", Name: "Unsaved", Type: "udp", Host: socket.LocalAddr().String()}, Domain: "example.com", QueryType: "TXT"}
	for range 2 {
		got, err := ctr.Test(t.Context(), request)
		if err != nil || got.Error != "" || got.Rcode != "NOERROR" || got.QueryType != "TXT" || got.Domain != "example.com." || len(got.Records) != 1 || !strings.Contains(got.Records[0].Value, "wire-test") {
			t.Fatalf("query = %+v, %v", got, err)
		}
	}
	if received.Load() != 2 {
		t.Fatalf("fresh tests sent %d queries", received.Load())
	}
	if _, ok := manager.resolvers.Load("draft"); ok {
		t.Fatal("test saved draft configuration")
	}
	if _, ok := manager.store.Load("draft"); ok {
		t.Fatal("test replaced an active resolver")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := ctr.Test(ctx, request)
	if err != nil || result.Error == "" {
		t.Fatalf("cancelled query = %+v, %v", result, err)
	}
	request.Domain = "https://example.com/"
	if _, err := ctr.Test(t.Context(), request); err == nil {
		t.Fatal("invalid domain accepted")
	}
	request.Domain = "example.com"
	request.QueryType = "OPT"
	if _, err := ctr.Test(t.Context(), request); err == nil {
		t.Fatal("message metadata query accepted")
	}
}
