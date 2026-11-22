package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/response"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/ringbuffer"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
)

// recorder is an in-memory DNSObserver that counts completions per trace.
type recorder struct {
	mu      sync.Mutex
	records []*netapi.DNSTraceData
	ch      chan *netapi.DNSTraceData
}

func newRecorder() *recorder { return &recorder{ch: make(chan *netapi.DNSTraceData, 64)} }

func (r *recorder) BeginDNS(transport, source string) *netapi.DNSTrace {
	return netapi.NewDNSTrace(transport, source, r.sink)
}

func (r *recorder) sink(d *netapi.DNSTraceData) {
	r.mu.Lock()
	r.records = append(r.records, d)
	r.mu.Unlock()
	r.ch <- d
}

func (r *recorder) next(t *testing.T) *netapi.DNSTraceData {
	t.Helper()
	select {
	case d := <-r.ch:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("no DNS history record")
		return nil
	}
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}

func query(t testing.TB, name string, qtype uint16, udpSize uint16) []byte {
	t.Helper()
	q := netapi.NewDNSMsg(netapi.DNSQuestion{Name: name, Qtype: qtype, Qclass: dns.ClassINET})
	q.Response, q.ID, q.UDPSize = false, 0x1234, udpSize
	if err := q.Pack(); err != nil {
		t.Fatal(err)
	}
	return q.Data
}

func answerFor(req *resolver.Request, rcode uint16, rrs ...dns.RR) *dns.Msg {
	m := &dns.Msg{ID: req.ID, Response: true, RecursionAvailable: true, Rcode: rcode, Answer: rrs}
	return m
}

func hdr(name string) dns.Header { return dns.Header{Name: name, Class: dns.ClassINET, TTL: 60} }

func historyServer(t *testing.T, listen string, transport resolver.Transport) (*dnsServer, *recorder) {
	t.Helper()
	rec := newRecorder()
	upstream := resolver.NewClient(resolver.Config{Name: "test-upstream", Label: "Test", PublicHost: "192.0.2.53:53", Type: "udp"}, transport)
	agent := NewServer(listen, upstream, rec).(*dnsServer)
	t.Cleanup(func() { _ = agent.Close(); _ = upstream.Close() })
	return agent, rec
}

// datagram runs a hijack-style request and returns the wire response.
func datagram(t *testing.T, agent *dnsServer, ctx context.Context, trace *netapi.DNSTrace, q []byte, write func([]byte) error) (<-chan error, error) {
	t.Helper()
	packet := netapi.NewPacket(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5555}, netapi.EmptyAddr, pool.Clone(q), nil)
	defer packet.DecRef()
	done := make(chan error, 1)
	err := agent.DoDatagram(ctx, &netapi.DNSRawRequest{Question: packet, Trace: trace, WriteBack: write, Done: func(err error) { done <- err }})
	return done, err
}

func sentWriter(trace *netapi.DNSTrace, out chan<- []byte) func([]byte) error {
	return func(b []byte) error {
		trace.AddSent(len(b))
		if out != nil {
			out <- append([]byte(nil), b...)
		}
		return nil
	}
}

func TestHistoryLocalUDPServer(t *testing.T) {
	agent, rec := historyServer(t, "127.0.0.1:0", resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		return answerFor(req, dns.RcodeSuccess, &dns.A{Hdr: hdr(req.Question.Name), Addr: netip.MustParseAddr("203.0.113.10")}), nil
	}))
	conn, err := net.Dial("udp", agent.udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i, wantCache := range []string{netapi.DNSCacheMiss, netapi.DNSCacheHit} {
		if _, err := conn.Write(query(t, "www.example.com.", dns.TypeA, 0)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		reply := &dns.Msg{Data: buf[:n]}
		if err := reply.Unpack(); err != nil || len(reply.Answer) != 1 {
			t.Fatalf("reply %d: %v %v", i, err, reply)
		}
		d := rec.next(t)
		if d.Transport != "udp" || d.SourceType != netapi.DNSSourceLocal || d.ClientIP != "127.0.0.1" || d.ClientPort == 0 {
			t.Fatalf("client = %+v", d)
		}
		if d.Domain != "www.example.com." || d.QType != dns.TypeA || d.TransactionID != 0x1234 || d.RequestSize == 0 {
			t.Fatalf("request = %+v", d)
		}
		if d.Outcome != netapi.DNSOutcomeSuccess || d.CacheStatus != wantCache || d.SentBytes != n || d.ResponseSize != n {
			t.Fatalf("query %d outcome=%s cache=%s sent=%d size=%d n=%d", i, d.Outcome, d.CacheStatus, d.SentBytes, d.ResponseSize, n)
		}
		if d.Resolver != "test-upstream" || d.ResolverLabel != "Test" || d.Server != "192.0.2.53:53" {
			t.Fatalf("server = %q %q %q", d.Resolver, d.ResolverLabel, d.Server)
		}
		if wantCache == netapi.DNSCacheMiss && (len(d.Attempts) != 1 || d.Source != netapi.DNSResolutionUpstream || d.Admission != "queued") {
			t.Fatalf("miss attempts=%v source=%s admission=%s", d.Attempts, d.Source, d.Admission)
		}
		if wantCache == netapi.DNSCacheHit && (len(d.Attempts) != 0 || d.Source != netapi.DNSResolutionCache || d.Admission != "cache_hit") {
			t.Fatalf("hit attempts=%v source=%s admission=%s", d.Attempts, d.Source, d.Admission)
		}
	}
}

func TestHistoryLocalTCPServer(t *testing.T) {
	agent, rec := historyServer(t, "127.0.0.1:0", resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		return answerFor(req, dns.RcodeSuccess, &dns.TXT{Hdr: hdr(req.Question.Name), Txt: []string{"v=spf1 -all"}}), nil
	}))
	conn, err := net.Dial("tcp", agent.tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := query(t, "txt.example.", dns.TypeTXT, 0)
	if err := binary.Write(conn, binary.BigEndian, uint16(len(q))); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(q); err != nil {
		t.Fatal(err)
	}
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, length)); err != nil {
		t.Fatal(err)
	}
	d := rec.next(t)
	if d.Transport != "tcp" || d.SourceType != netapi.DNSSourceLocal || d.ClientIP != "127.0.0.1" || d.QType != dns.TypeTXT || d.SentBytes != int(length) {
		t.Fatalf("tcp record = %+v", d)
	}
}

func TestHistoryHijackStreamFinishesSuppliedTrace(t *testing.T) {
	agent, _ := historyServer(t, "", resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		return answerFor(req, dns.RcodeSuccess, &dns.A{Hdr: hdr(req.Question.Name), Addr: netip.MustParseAddr("192.0.2.7")}), nil
	}))
	rec := newRecorder()
	trace := rec.BeginDNS("tcp", netapi.DNSSourceHijack)
	trace.SetInbound("tun0", "TUN")
	client, server := net.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- agent.DoStream(t.Context(), &netapi.DNSStreamRequest{Conn: server, Trace: trace, ForceFakeIP: true})
	}()
	q := query(t, "hijack.example.", dns.TypeA, 0)
	_ = binary.Write(client, binary.BigEndian, uint16(len(q)))
	_, _ = client.Write(q)
	var length uint16
	_ = binary.Read(client, binary.BigEndian, &length)
	_, _ = io.ReadFull(client, make([]byte, length))
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	d := rec.next(t)
	if d.SourceType != netapi.DNSSourceHijack || d.InboundID != "tun0" || !d.ForceFakeIP || d.Outcome != netapi.DNSOutcomeSuccess {
		t.Fatalf("hijack stream = %+v", d)
	}
	if rec.count() != 1 {
		t.Fatalf("completions = %d", rec.count())
	}
}

func TestHistoryRecordsQueryTypesAndSections(t *testing.T) {
	https := &dns.HTTPS{}
	https.Hdr, https.Priority, https.Target = hdr("svc.example."), 1, "."
	cases := []struct {
		name  string
		qtype uint16
		rr    dns.RR
		data  string
	}{
		{"a.example.", dns.TypeA, &dns.A{Hdr: hdr("a.example."), Addr: netip.MustParseAddr("192.0.2.1")}, "192.0.2.1"},
		{"aaaa.example.", dns.TypeAAAA, &dns.AAAA{Hdr: hdr("aaaa.example."), Addr: netip.MustParseAddr("2001:db8::1")}, "2001:db8::1"},
		{"svc.example.", dns.TypeHTTPS, https, "1 ."},
		{"1.2.0.192.in-addr.arpa.", dns.TypePTR, &dns.PTR{Hdr: hdr("1.2.0.192.in-addr.arpa."), Ptr: "host.example."}, "host.example."},
		{"mx.example.", dns.TypeMX, &dns.MX{Hdr: hdr("mx.example."), Preference: 10, Mx: "mail.example."}, "10 mail.example."},
	}
	agent, _ := historyServer(t, "", resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		for _, c := range cases {
			if c.name == req.Question.Name {
				m := answerFor(req, dns.RcodeSuccess, c.rr)
				m.Ns = []dns.RR{&dns.NS{Hdr: hdr("example."), Ns: "ns1.example."}}
				return m, nil
			}
		}
		return nil, errors.New("unexpected")
	}))
	for _, c := range cases {
		rec := newRecorder()
		trace := rec.BeginDNS("udp", netapi.DNSSourceHijack)
		done, err := datagram(t, agent, t.Context(), trace, query(t, c.name, c.qtype, 1232), sentWriter(trace, nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(c.name, err)
		}
		d := rec.next(t)
		if d.QType != c.qtype || d.Response == nil || len(d.Response.Answer) != 1 || len(d.Response.Authority) != 1 || d.Outcome != netapi.DNSOutcomeSuccess {
			t.Fatalf("%s: %+v", c.name, d)
		}
		if got := d.Response.Answer[0].Data().String(); c.data != "" && !strings.Contains(got, c.data) {
			t.Fatalf("%s rdata = %q", c.name, got)
		}
		if d.RequestUDPSize != 1232 {
			t.Fatalf("udp size = %d", d.RequestUDPSize)
		}
	}
}

func TestHistoryRcodeOutcomes(t *testing.T) {
	cases := map[string]struct {
		rcode   uint16
		answer  bool
		outcome string
	}{
		"nx.example.":      {dns.RcodeNameError, false, netapi.DNSOutcomeNXDomain},
		"nodata.example.":  {dns.RcodeSuccess, false, netapi.DNSOutcomeNoData},
		"fail.example.":    {dns.RcodeServerFailure, false, netapi.DNSOutcomeServFail},
		"refused.example.": {dns.RcodeRefused, false, netapi.DNSOutcomeRefused},
		"cname.example.":   {dns.RcodeSuccess, true, netapi.DNSOutcomeNoData},
	}
	agent, _ := historyServer(t, "", resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		c := cases[req.Question.Name]
		m := answerFor(req, c.rcode)
		if c.answer { // A CNAME without the asked type is still NODATA.
			m.Answer = []dns.RR{&dns.CNAME{Hdr: hdr(req.Question.Name), Target: "target.example."}}
		}
		return m, nil
	}))
	for name, c := range cases {
		rec := newRecorder()
		trace := rec.BeginDNS("udp", netapi.DNSSourceHijack)
		done, err := datagram(t, agent, t.Context(), trace, query(t, name, dns.TypeA, 0), sentWriter(trace, nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("%s: delivered rcode must not be an error: %v", name, err)
		}
		d := rec.next(t)
		if d.Outcome != c.outcome || d.Response.Rcode != c.rcode || d.FailureStage != "" {
			t.Fatalf("%s outcome=%s rcode=%d stage=%s", name, d.Outcome, d.Response.Rcode, d.FailureStage)
		}
	}
}

func TestHistoryCustomResponseBypassesCache(t *testing.T) {
	rec := newRecorder()
	upstream := netapi.ErrorResolver(func(string) error { return errors.New("upstream used") })
	rules := response.New(upstream)
	if err := rules.Apply(contract.ResponseRules{Rules: []contract.ResponseRule{{Domain: "custom.example", QueryType: "A", Rcode: "NOERROR", Answers: []string{"198.51.100.4"}}}}); err != nil {
		t.Fatal(err)
	}
	agent := NewServer("", rules, rec).(*dnsServer)
	defer agent.Close()
	trace := rec.BeginDNS("udp", netapi.DNSSourceLocal)
	if _, err := datagram(t, agent, t.Context(), trace, query(t, "custom.example.", dns.TypeA, 0), sentWriter(trace, nil)); err != nil {
		t.Fatal(err)
	}
	d := rec.next(t)
	if d.Source != netapi.DNSResolutionCustom || d.CacheStatus != netapi.DNSCacheBypass || d.Outcome != netapi.DNSOutcomeSuccess || d.Admission != "cache_hit" {
		t.Fatalf("custom = source %s cache %s outcome %s admission %s", d.Source, d.CacheStatus, d.Outcome, d.Admission)
	}
}

func TestHistoryUpstreamTimeoutAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		agent, _ := historyServer(t, "", resolver.TransportFunc(func(ctx context.Context, _ *resolver.Request) (*dns.Msg, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}))
		rec := newRecorder()
		trace := rec.BeginDNS("udp", netapi.DNSSourceHijack)
		if _, err := datagram(t, agent, t.Context(), trace, query(t, "slow.example.", dns.TypeA, 0), sentWriter(trace, nil)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(configuration.ResolverTimeout + time.Second)
		synctest.Wait()
		d := rec.next(t)
		if d.Outcome != netapi.DNSOutcomeTimeout || d.FailureStage != netapi.DNSStageUpstream || len(d.Attempts) != 1 || d.Attempts[0].Result != netapi.DNSOutcomeTimeout {
			t.Fatalf("timeout = %+v", d)
		}

		ctx, cancel := context.WithCancel(t.Context())
		trace = rec.BeginDNS("udp", netapi.DNSSourceHijack)
		if _, err := datagram(t, agent, ctx, trace, query(t, "cancel.example.", dns.TypeA, 0), sentWriter(trace, nil)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		cancel()
		synctest.Wait()
		d = rec.next(t)
		if d.Outcome != netapi.DNSOutcomeCanceled {
			t.Fatalf("cancel outcome = %s (%s)", d.Outcome, d.Error)
		}
	})
}

// queueOnlyServer has no dispatch workers, so queued requests stay queued.
func queueOnlyServer(t *testing.T, queue int, transport resolver.Transport) *dnsServer {
	ctx, cancel := context.WithCancel(t.Context())
	upstream := resolver.NewClient(resolver.Config{}, transport)
	agent := &dnsServer{ctx: ctx, cancel: cancel, notifyChan: make(chan struct{}, 1), resolver: upstream,
		reqBuffer: ringbuffer.NewRingBuffer[*queuedRequest](1, func() int { return queue }), udpSemaphore: semaphore.NewSemaphore(1)}
	t.Cleanup(func() { _ = agent.Close(); _ = upstream.Close() })
	return agent
}

func neverAnswer(ctx context.Context, _ *resolver.Request) (*dns.Msg, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestHistoryAdmissionDrops(t *testing.T) {
	previous := configuration.MaxUDPUnprocessedPackets.Load()
	defer configuration.MaxUDPUnprocessedPackets.Store(previous)

	t.Run("queue_full", func(t *testing.T) {
		configuration.MaxUDPUnprocessedPackets.Store(4)
		agent := queueOnlyServer(t, 1, resolver.TransportFunc(neverAnswer))
		rec := newRecorder()
		if _, err := datagram(t, agent, t.Context(), rec.BeginDNS("udp", netapi.DNSSourceHijack), query(t, "first.example.", dns.TypeA, 0), nil); err != nil {
			t.Fatal(err)
		}
		_, err := datagram(t, agent, t.Context(), rec.BeginDNS("udp", netapi.DNSSourceHijack), query(t, "second.example.", dns.TypeA, 0), nil)
		if err == nil {
			t.Fatal("second request was admitted")
		}
		d := rec.next(t)
		if d.Domain != "second.example." || d.Outcome != netapi.DNSOutcomeDropped || d.FailureStage != netapi.DNSStageAdmission || d.FailureReason != "queue_full" {
			t.Fatalf("queue full = %+v", d)
		}
	})
	t.Run("budget_full", func(t *testing.T) {
		configuration.MaxUDPUnprocessedPackets.Store(0)
		agent := queueOnlyServer(t, 8, resolver.TransportFunc(neverAnswer))
		rec := newRecorder()
		if _, err := datagram(t, agent, t.Context(), rec.BeginDNS("udp", netapi.DNSSourceHijack), query(t, "first.example.", dns.TypeA, 0), nil); err != nil {
			t.Fatal(err)
		}
		if _, err := datagram(t, agent, t.Context(), rec.BeginDNS("udp", netapi.DNSSourceHijack), query(t, "second.example.", dns.TypeA, 0), nil); err == nil {
			t.Fatal("second request was admitted")
		}
		if d := rec.next(t); d.FailureReason != "budget_full" || d.Outcome != netapi.DNSOutcomeDropped {
			t.Fatalf("budget full = %+v", d)
		}
	})
	t.Run("expired", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			configuration.MaxUDPUnprocessedPackets.Store(4)
			agent := queueOnlyServer(t, 4, resolver.TransportFunc(neverAnswer))
			rec := newRecorder()
			if _, err := datagram(t, agent, t.Context(), rec.BeginDNS("udp", netapi.DNSSourceHijack), query(t, "late.example.", dns.TypeA, 0), nil); err != nil {
				t.Fatal(err)
			}
			time.Sleep(configuration.ResolverTimeout + time.Second)
			agent.handle()
			if d := rec.next(t); d.FailureReason != "expired" || d.Outcome != netapi.DNSOutcomeDropped || d.QueueWait < configuration.ResolverTimeout {
				t.Fatalf("expired = %+v", d)
			}
		})
	})
	t.Run("shutdown", func(t *testing.T) {
		configuration.MaxUDPUnprocessedPackets.Store(4)
		agent := queueOnlyServer(t, 4, resolver.TransportFunc(neverAnswer))
		rec := newRecorder()
		done, err := datagram(t, agent, t.Context(), rec.BeginDNS("udp", netapi.DNSSourceHijack), query(t, "closing.example.", dns.TypeA, 0), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = agent.Close()
		if err := <-done; err == nil {
			t.Fatal("shutdown completed without an error")
		}
		if d := rec.next(t); d.FailureReason != "shutdown" || d.Outcome != netapi.DNSOutcomeDropped {
			t.Fatalf("shutdown = %+v", d)
		}
		if rec.count() != 1 {
			t.Fatalf("completions = %d", rec.count())
		}
	})
}

func TestHistoryMalformedPacketIsRecordedOnce(t *testing.T) {
	rec := newRecorder()
	agent := NewServer("", netapi.ErrorResolver(nil), rec).(*dnsServer)
	defer agent.Close()
	called := false
	packet := netapi.NewPacket(&net.UDPAddr{}, netapi.EmptyAddr, pool.Clone([]byte{0, 1, 2}), nil)
	defer packet.DecRef()
	err := agent.DoDatagram(t.Context(), &netapi.DNSRawRequest{Question: packet, Trace: rec.BeginDNS("udp", netapi.DNSSourceHijack), Done: func(error) { called = true }})
	if err == nil || called {
		t.Fatalf("malformed admission err=%v done=%t", err, called)
	}
	d := rec.next(t)
	if d.Outcome != netapi.DNSOutcomeMalformed || d.FailureStage != netapi.DNSStageIngress || d.RequestSize != 3 || d.Domain != "" {
		t.Fatalf("malformed = %+v", d)
	}
}

func TestHistoryUDPTruncation(t *testing.T) {
	agent, _ := historyServer(t, "", resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		var rrs []dns.RR
		for i := range 60 {
			rrs = append(rrs, &dns.A{Hdr: hdr(req.Question.Name), Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})})
		}
		return answerFor(req, dns.RcodeSuccess, rrs...), nil
	}))
	rec := newRecorder()
	trace := rec.BeginDNS("udp", netapi.DNSSourceHijack)
	out := make(chan []byte, 1)
	if _, err := datagram(t, agent, t.Context(), trace, query(t, "big.example.", dns.TypeA, 0), sentWriter(trace, out)); err != nil {
		t.Fatal(err)
	}
	wire := <-out
	d := rec.next(t)
	if !d.ServerTruncate || !d.Response.Truncated || len(wire) > 512 || d.ResponseSize != len(wire) || d.SentBytes != len(wire) {
		t.Fatalf("truncated=%t tc=%t size=%d sent=%d wire=%d", d.ServerTruncate, d.Response.Truncated, d.ResponseSize, d.SentBytes, len(wire))
	}
	if len(d.Response.Answer) != 60 {
		t.Fatalf("resolved records kept = %d", len(d.Response.Answer))
	}
}

func TestHistoryDeliveryFailures(t *testing.T) {
	agent, _ := historyServer(t, "", resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		return answerFor(req, dns.RcodeSuccess, &dns.A{Hdr: hdr(req.Question.Name), Addr: netip.MustParseAddr("192.0.2.9")}), nil
	}))
	t.Run("write_error", func(t *testing.T) {
		rec := newRecorder()
		trace := rec.BeginDNS("udp", netapi.DNSSourceHijack)
		done, err := datagram(t, agent, t.Context(), trace, query(t, "write.example.", dns.TypeA, 0), func([]byte) error { return errors.New("socket closed") })
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Fatal("write failure was not reported")
		}
		d := rec.next(t)
		if d.Outcome != netapi.DNSOutcomeWriteError || d.FailureStage != netapi.DNSStageDelivery || d.FailureReason != "write_failed" || d.Response == nil {
			t.Fatalf("write error = %+v", d)
		}
	})
	t.Run("partial_write", func(t *testing.T) {
		rec := newRecorder()
		trace := rec.BeginDNS("udp", netapi.DNSSourceHijack)
		done, err := datagram(t, agent, t.Context(), trace, query(t, "partial.example.", dns.TypeA, 0), func(b []byte) error { trace.AddSent(len(b) / 2); return nil })
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		d := rec.next(t)
		if d.Outcome != netapi.DNSOutcomeWriteError || d.FailureReason != "partial_write" || d.SentBytes != d.ResponseSize/2 {
			t.Fatalf("partial = %+v", d)
		}
	})
	t.Run("traffic_control", func(t *testing.T) {
		rec := newRecorder()
		trace := rec.BeginDNS("udp", netapi.DNSSourceHijack)
		done, err := datagram(t, agent, t.Context(), trace, query(t, "quota.example.", dns.TypeA, 0), func([]byte) error {
			err := errors.New("download quota exceeded")
			trace.Fail(netapi.DNSOutcomeRejected, netapi.DNSStageTrafficControl, "download_quota", err)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Fatal("quota rejection was not reported")
		}
		if d := rec.next(t); d.Outcome != netapi.DNSOutcomeRejected || d.FailureStage != netapi.DNSStageTrafficControl {
			t.Fatalf("traffic control = %+v", d)
		}
	})
}

func TestHistoryTruncatedUpstreamRetryAttempts(t *testing.T) {
	var calls atomic.Int32
	agent, _ := historyServer(t, "", resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		m := answerFor(req, dns.RcodeSuccess, &dns.A{Hdr: hdr(req.Question.Name), Addr: netip.MustParseAddr("192.0.2.10")})
		if calls.Add(1) == 1 {
			m.Truncated, m.Answer = true, nil
		}
		return m, nil
	}))
	rec := newRecorder()
	trace := rec.BeginDNS("udp", netapi.DNSSourceHijack)
	if _, err := datagram(t, agent, t.Context(), trace, query(t, "retry.example.", dns.TypeA, 0), sentWriter(trace, nil)); err != nil {
		t.Fatal(err)
	}
	d := rec.next(t)
	if len(d.Attempts) != 2 || d.Attempts[0].Result != "truncated" || d.Attempts[1].Result != "success" || d.Attempts[1].Transport != "udp+tc-retry" {
		t.Fatalf("attempts = %+v", d.Attempts)
	}
}

func TestHistoryDisabledObserverRecordsNothing(t *testing.T) {
	agent := NewServer("", netapi.ErrorResolver(nil)).(*dnsServer)
	defer agent.Close()
	if agent.begin("udp") != nil {
		t.Fatal("server without observer started a trace")
	}
	// A nil trace is accepted everywhere on the request path.
	done, err := datagram(t, agent, t.Context(), nil, query(t, "plain.example.", dns.TypeA, 0), func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("local answer was not synchronous")
	}
}

func TestHistoryExactlyOnceUnderConcurrency(t *testing.T) {
	agent, _ := historyServer(t, "", resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		return answerFor(req, dns.RcodeSuccess, &dns.A{Hdr: hdr(req.Question.Name), Addr: netip.MustParseAddr("192.0.2.11")}), nil
	}))
	var finished atomic.Int32
	sink := func(*netapi.DNSTraceData) { finished.Add(1) }
	var wg sync.WaitGroup
	const n = 200
	for i := range n {
		wg.Go(func() {
			trace := netapi.NewDNSTrace("udp", netapi.DNSSourceHijack, sink)
			name := "same.example."
			if i%2 == 0 {
				name = "other.example."
			}
			done, err := datagram(t, agent, t.Context(), trace, query(t, name, dns.TypeA, 0), sentWriter(trace, nil))
			if err == nil {
				if err := <-done; err != nil {
					t.Error(err)
				}
			}
			trace.Finish(errors.New("late duplicate"))
		})
	}
	wg.Wait()
	if got := finished.Load(); got != n {
		t.Fatalf("finished %d of %d", got, n)
	}
}
