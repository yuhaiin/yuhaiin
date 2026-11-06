package server

import (
	"codeberg.org/miekg/dns"
	"context"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"net"
	"net/netip"
	"testing"
)

func admissionAnswer(req *resolver.Request, ttl uint32) *dns.Msg {
	return &dns.Msg{ID: req.ID, Response: true, Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: ttl}, Addr: netip.MustParseAddr("192.0.2.1")}}}
}
func admissionServer(tb testing.TB, limit int64, transport resolver.Transport) (*dnsServer, netapi.Resolver) {
	tb.Helper()
	previous := configuration.DNSProcessThread.Load()
	configuration.DNSProcessThread.Store(limit)
	defer configuration.DNSProcessThread.Store(previous)
	upstream := resolver.NewClient(resolver.Config{}, transport)
	agent := NewServer("", upstream).(*dnsServer)
	tb.Cleanup(func() { _ = agent.Close(); _ = upstream.Close() })
	return agent, upstream
}
func admissionQuery(tb testing.TB, name string) []byte {
	tb.Helper()
	q := netapi.NewDNSMsg(netapi.DNSQuestion{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
	q.Response = false
	if err := q.Pack(); err != nil {
		tb.Fatal(err)
	}
	return q.Data
}
func admissionEnqueue(tb testing.TB, agent *dnsServer, ctx context.Context, query []byte) <-chan error {
	tb.Helper()
	packet := netapi.NewPacket(&net.UDPAddr{}, netapi.EmptyAddr, pool.Clone(query), nil)
	defer packet.DecRef()
	done := make(chan error, 1)
	if err := agent.DoDatagram(ctx, &netapi.DNSRawRequest{Question: packet, WriteBack: func([]byte) error { return nil }, Done: func(err error) { done <- err }}); err != nil {
		tb.Fatal(err)
	}
	return done
}
