package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

var admissionMetrics = sync.OnceValue(metrics.NewPrometheus)

func BenchmarkDNSDatagramAdmission(b *testing.B) { benchmarkDatagramAdmission(b) }
func BenchmarkDNSDatagramAdmissionPrometheus(b *testing.B) {
	previous := metrics.Counter
	metrics.Counter = admissionMetrics()
	b.Cleanup(func() { metrics.Counter = previous })
	benchmarkDatagramAdmission(b)
}

func benchmarkDatagramAdmission(b *testing.B) {
	for _, cached := range []bool{true, false} {
		b.Run(map[bool]string{true: "cached", false: "uncached"}[cached], func(b *testing.B) {
			ttl := uint32(0)
			if cached {
				ttl = 600
			}
			agent, upstream := admissionServer(b, 150, resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
				return admissionAnswer(req, ttl), nil
			}))
			if cached {
				if _, err := upstream.Raw(b.Context(), netapi.DNSQuestion{Name: "bench.example.", Qtype: dns.TypeA}); err != nil {
					b.Fatal(err)
				}
			}
			query := admissionQuery(b, "bench.example.")
			done := make(chan error, 1)
			write := func([]byte) error { return nil }
			complete := func(err error) { done <- err }
			b.ReportAllocs()
			for b.Loop() {
				req := &netapi.DNSRawRequest{Question: netapi.NewPacket(nil, nil, pool.Clone(query), nil), WriteBack: write, Done: complete}
				err := agent.DoDatagram(b.Context(), req)
				req.Question.DecRef()
				if err != nil {
					b.Fatal(err)
				}
				if err := <-done; err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDNSCachedBehindSlowQuery(b *testing.B) {
	var release chan struct{}
	started := make(chan struct{}, 1)
	agent, upstream := admissionServer(b, 1, resolver.TransportFunc(func(ctx context.Context, req *resolver.Request) (*dns.Msg, error) {
		if req.Question.Name == "slow.example." {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return admissionAnswer(req, func() uint32 {
			if req.Question.Name == "slow.example." {
				return 0
			}
			return 600
		}()), nil
	}))
	if _, err := upstream.Raw(b.Context(), netapi.DNSQuestion{Name: "cached.example.", Qtype: dns.TypeA}); err != nil {
		b.Fatal(err)
	}
	slow := admissionQuery(b, "slow.example.")
	cached := admissionQuery(b, "cached.example.")
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		release = make(chan struct{})
		slowDone := admissionEnqueue(b, agent, b.Context(), slow)
		<-started
		time.AfterFunc(time.Millisecond, func() { close(release) })
		b.StartTimer()
		done := admissionEnqueue(b, agent, b.Context(), cached)
		if err := <-done; err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if err := <-slowDone; err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// Zero TTL forces every request through the real UDP transport on loopback.
// This separates admission overhead from the unrealistic in-memory upstream.
func BenchmarkDNSDatagramUDPMiss(b *testing.B) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buf := make([]byte, 2048)
		for {
			n, addr, err := listener.ReadFrom(buf)
			if err != nil {
				return
			}
			query := &dns.Msg{Data: buf[:n]}
			if query.Unpack() != nil {
				return
			}
			msg := admissionAnswer(&resolver.Request{ID: query.ID, Question: netapi.DNSQuestionFromRR(query.Question[0])}, 0)
			msg.Question = query.Question
			if msg.Pack() != nil {
				return
			}
			if _, err := listener.WriteTo(msg.Data, addr); err != nil {
				return
			}
		}
	}()
	b.Cleanup(func() { _ = listener.Close(); <-stopped })
	transport, err := resolver.NewDoU(resolver.Config{Host: listener.LocalAddr().String(), Dialer: direct.Default})
	if err != nil {
		b.Fatal(err)
	}
	agent, _ := admissionServer(b, 150, transport)
	b.Cleanup(func() { _ = transport.Close() })
	query := admissionQuery(b, "udp-miss.example.")
	done := make(chan error, 1)
	write := func([]byte) error { return nil }
	complete := func(err error) { done <- err }
	b.ReportAllocs()
	for b.Loop() {
		req := &netapi.DNSRawRequest{Question: netapi.NewPacket(nil, nil, pool.Clone(query), nil), WriteBack: write, Done: complete}
		err := agent.DoDatagram(b.Context(), req)
		req.Question.DecRef()
		if err != nil {
			b.Fatal(err)
		}
		if err := <-done; err != nil {
			b.Fatal(err)
		}
	}
}
