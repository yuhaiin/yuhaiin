package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/response"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

// This supplement includes the real route matcher and UDP upstream transport.
// Zero-TTL answers ensure every miss crosses both loopback UDP hops.
func BenchmarkDNSRoutedUDPPipeline(b *testing.B) {
	for _, cached := range []bool{true, false} {
		b.Run(fmt.Sprintf("upstream-cache=%t", cached), func(b *testing.B) {
			upstreamSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			done := make(chan struct{})
			var upstreamQueries atomic.Int64
			b.Cleanup(func() { _ = upstreamSocket.Close(); <-done })
			go func() {
				defer close(done)
				buf := make([]byte, 4096)
				for {
					n, addr, err := upstreamSocket.ReadFrom(buf)
					if err != nil {
						return
					}
					q := &dns.Msg{Data: buf[:n]}
					if err := q.Unpack(); err != nil {
						return
					}
					question := netapi.DNSQuestionFromRR(q.Question[0])
					upstreamQueries.Add(1)
					msg := netapi.NewDNSMsg(question)
					msg.ID = q.ID
					ttl := uint32(0)
					if cached {
						ttl = 600
					}
					header := dns.Header{Name: question.Name, TTL: ttl, Class: dns.ClassINET}
					switch question.Qtype {
					case dns.TypeA:
						msg.Answer = []dns.RR{&dns.A{Hdr: header, Addr: netip.MustParseAddr("192.0.2.1")}}
					case dns.TypeAAAA:
						msg.Answer = []dns.RR{&dns.AAAA{Hdr: header, Addr: netip.MustParseAddr("2001:db8::1")}}
					}
					if err := msg.Pack(); err != nil {
						return
					}
					if _, err := upstreamSocket.WriteTo(msg.Data, addr); err != nil {
						return
					}
				}
			}()
			// NewLists cleans orphan indexes in DataDir; keep that inside this
			// benchmark's temporary directory, never the user's configuration.
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
			if err := settings.SaveSettings(b.Context(), store.RouteSettings{DefaultMode: "proxy", DirectResolver: "local-upstream", ProxyResolver: "local-upstream"}); err != nil {
				b.Fatal(err)
			}
			upstream := NewResolver(direct.Default)
			upstream.Apply(contract.Resolver{ID: "local-upstream", Type: "udp", Host: upstreamSocket.LocalAddr().String()})
			b.Cleanup(func() { _ = upstream.Close() })
			lists := route.NewLists(store.NewRouteListStore(db.DB()), settings, dataDir)
			b.Cleanup(func() { _ = lists.Close() })
			router := route.NewRoute(nil, upstream, lists, nil)
			routing := route.NewRules(store.NewRouteRuleStore(db.DB()), settings, router)
			b.Cleanup(func() { _ = routing.Close() })
			if err := routing.Apply(b.Context()); err != nil {
				b.Fatal(err)
			}
			hosts := NewHosts(nil, router)
			fake, err := NewFakeDNS(nil, hosts, filepath.Join(dataDir, "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = fake.Close() })
			rules := response.New(fake)
			config := contract.ResponseRules{}
			for i := range 10000 {
				config.Rules = append(config.Rules, contract.ResponseRule{Domain: fmt.Sprintf("*.d%d.example", i), QueryType: "HTTPS", Rcode: "NXDOMAIN"})
			}
			if err := rules.Apply(config); err != nil {
				b.Fatal(err)
			}
			q := netapi.DNSQuestion{Name: "cache.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
			if _, err := rules.Raw(netapi.WithContext(b.Context()), q); err != nil {
				b.Fatal(err)
			}
			agent := server.NewServer("", rules)
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
			_ = client.SetDeadline(time.Now().Add(5 * time.Minute))
			query := netapi.NewDNSMsg(q)
			query.Response = false
			if err := query.Pack(); err != nil {
				b.Fatal(err)
			}
			buf := make([]byte, 4096)
			b.ReportAllocs()
			initialQueries := upstreamQueries.Load()
			for b.Loop() {
				if _, err := client.Write(query.Data); err != nil {
					b.Fatal(err)
				}
				if n, err := client.Read(buf); err != nil || n < 12 {
					b.Fatalf("DNS response: %d bytes, %v", n, err)
				}
			}
			b.ReportMetric(float64(upstreamQueries.Load()-initialQueries)/float64(b.N), "upstream-queries/op")
		})
	}
}
