package resolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	dnsresolver "github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/response"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type historySink chan *netapi.DNSTraceData

func (s historySink) BeginDNS(transport, source string) *netapi.DNSTrace {
	return netapi.NewDNSTrace(transport, source, func(d *netapi.DNSTraceData) { s <- d })
}

// historyChain is the application's resolver order: custom responses, FakeIP,
// hosts, then the upstream client.
type historyChain struct {
	agent   netapi.DNSAgent
	fakedns *Fakedns
	hosts   *Hosts
	sink    historySink
}

func newHistoryChain(t *testing.T, upstream func(*dnsresolver.Request) *dns.Msg) *historyChain {
	t.Helper()
	client := dnsresolver.NewClient(dnsresolver.Config{Name: "up", Type: "udp"}, dnsresolver.TransportFunc(func(_ context.Context, req *dnsresolver.Request) (*dns.Msg, error) {
		return upstream(req), nil
	}))
	hosts := NewHosts(netapi.NewErrProxy(errors.New("no dial")), client)
	f, err := NewFakeDNS(netapi.NewErrProxy(errors.New("no dial")), hosts, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	sink := make(historySink, 8)
	agent := server.NewServer("", response.New(f), sink)
	t.Cleanup(func() { _ = agent.Close(); _ = f.Close() })
	return &historyChain{agent: agent, fakedns: f, hosts: hosts, sink: sink}
}

func (c *historyChain) query(t *testing.T, name string, qtype uint16, force bool) *netapi.DNSTraceData {
	t.Helper()
	q := netapi.NewDNSMsg(netapi.DNSQuestion{Name: name, Qtype: qtype, Qclass: dns.ClassINET})
	q.Response = false
	if err := q.Pack(); err != nil {
		t.Fatal(err)
	}
	trace := c.sink.BeginDNS("udp", netapi.DNSSourceHijack)
	packet := netapi.NewPacket(&net.UDPAddr{}, netapi.EmptyAddr, pool.Clone(q.Data), nil)
	defer packet.DecRef()
	err := c.agent.DoDatagram(t.Context(), &netapi.DNSRawRequest{Question: packet, Trace: trace, ForceFakeIP: force,
		WriteBack: func(b []byte) error { trace.AddSent(len(b)); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-c.sink:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("no history record")
		return nil
	}
}

func realAnswer(req *dnsresolver.Request) *dns.Msg {
	m := &dns.Msg{ID: req.ID, Response: true}
	h := dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 60}
	switch req.Question.Qtype {
	case dns.TypeA:
		if req.Question.Name == "missing.example." {
			m.Rcode = dns.RcodeNameError
			return m
		}
		m.Answer = []dns.RR{&dns.A{Hdr: h, Addr: netip.MustParseAddr("203.0.113.10")}}
	case dns.TypeAAAA:
		m.Answer = []dns.RR{&dns.AAAA{Hdr: h, Addr: netip.MustParseAddr("2001:db8::10")}}
	}
	return m
}

func TestDNSHistoryFakeIPObservations(t *testing.T) {
	t.Run("global_ipv4", func(t *testing.T) {
		c := newHistoryChain(t, realAnswer)
		if err := c.fakedns.Apply(contractresolver.FakeDNS{Enabled: true}); err != nil {
			t.Fatal(err)
		}
		d := c.query(t, "www.example.com.", dns.TypeA, false)
		if !d.FakeIPRequested || !d.FakeIPReturned || d.FakeIPReason != "global_fakeip_enabled" || d.ForceFakeIP || d.Source != netapi.DNSResolutionFakeIP {
			t.Fatalf("fakeip = %+v", d)
		}
		ip := netip.MustParseAddr(d.FakeIPv4)
		pool := netip.MustParsePrefix(d.FakeIPPoolIPv4)
		if !pool.Contains(ip) || d.FakeIPAllocation != "allocated" {
			t.Fatalf("ip %s not in pool %s (%s)", ip, pool, d.FakeIPAllocation)
		}
		// The returned address is the live mapping in fakeip_entries.
		if domain, ok := c.fakedns.fake.GetDomainFromIP(ip); !ok || domain != "www.example.com" {
			t.Fatalf("mapping = %q %t", domain, ok)
		}
	})
	t.Run("force_ipv6", func(t *testing.T) {
		c := newHistoryChain(t, realAnswer)
		d := c.query(t, "v6.example.", dns.TypeAAAA, true)
		if !d.FakeIPReturned || d.FakeIPReason != "force_fakeip" || !d.ForceFakeIP || d.FakeIPGlobal || d.FakeIPv6 == "" || d.FakeIPv4 != "" {
			t.Fatalf("force ipv6 = %+v", d)
		}
		if !netip.MustParsePrefix(d.FakeIPPoolIPv6).Contains(netip.MustParseAddr(d.FakeIPv6)) {
			t.Fatal("ipv6 outside pool")
		}
	})
	t.Run("force_whitelisted", func(t *testing.T) {
		c := newHistoryChain(t, realAnswer)
		useTestLists(c.fakedns, map[string][]string{"wl": {"bank.example"}})
		if err := c.fakedns.Apply(contractresolver.FakeDNS{WhitelistListIDs: []string{"wl"}}); err != nil {
			t.Fatal(err)
		}
		d := c.query(t, "bank.example.", dns.TypeA, true)
		if d.FakeIPRequested || d.FakeIPReturned || d.FakeIPReason != "whitelist" || !d.ForceFakeIP || d.Source != netapi.DNSResolutionUpstream {
			t.Fatalf("whitelist = %+v", d)
		}
		if d.Response == nil || d.Response.Answer[0].(*dns.A).Addr != netip.MustParseAddr("203.0.113.10") {
			t.Fatal("whitelisted name did not get the real answer")
		}
	})
	t.Run("disabled", func(t *testing.T) {
		c := newHistoryChain(t, realAnswer)
		d := c.query(t, "plain.example.", dns.TypeA, false)
		if d.FakeIPRequested || d.FakeIPReturned || d.FakeIPReason != "disabled" || d.FakeIPAllocation != "not_requested" {
			t.Fatalf("disabled = %+v", d)
		}
	})
	t.Run("upstream_nxdomain_is_not_faked", func(t *testing.T) {
		c := newHistoryChain(t, realAnswer)
		d := c.query(t, "missing.example.", dns.TypeA, true)
		if d.FakeIPReturned || d.FakeIPAllocation != "upstream_no_answer" || d.Outcome != netapi.DNSOutcomeNXDomain || d.FailureStage != "" {
			t.Fatalf("nxdomain = %+v", d)
		}
	})
	t.Run("not_applicable_qtype", func(t *testing.T) {
		c := newHistoryChain(t, realAnswer)
		d := c.query(t, "txt.example.", dns.TypeTXT, true)
		if d.FakeIPReturned || d.FakeIPAllocation != "not_applicable_qtype" || d.Outcome != netapi.DNSOutcomeNoData {
			t.Fatalf("txt = %+v", d)
		}
	})
}

func TestDNSHistoryHostsResponse(t *testing.T) {
	c := newHistoryChain(t, func(*dnsresolver.Request) *dns.Msg { panic("hosts answer reached upstream") })
	c.hosts.Apply(map[string]string{"router.lan": "192.168.1.1", "alias.example": "target.example"})
	d := c.query(t, "router.lan.", dns.TypeA, false)
	if d.Source != netapi.DNSResolutionHosts || d.CacheStatus != netapi.DNSCacheBypass || d.Outcome != netapi.DNSOutcomeSuccess || len(d.Attempts) != 0 {
		t.Fatalf("hosts = %+v", d)
	}
}

func TestDNSHistoryHostsRewriteRecordsUpstream(t *testing.T) {
	c := newHistoryChain(t, realAnswer)
	c.hosts.Apply(map[string]string{"alias.example": "target.example"})
	d := c.query(t, "alias.example.", dns.TypeA, false)
	if d.HostsRewrite != "target.example." || d.Source != netapi.DNSResolutionUpstream || len(d.Attempts) != 1 || d.Resolver != "up" {
		t.Fatalf("rewrite = %+v", d)
	}
}
