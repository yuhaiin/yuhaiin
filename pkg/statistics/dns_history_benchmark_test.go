package statistics

import (
	"context"
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func benchHistory(b *testing.B, options DNSHistoryOptions, enabled bool) *DNSHistory {
	b.Helper()
	store, err := storagesqlite.Open(b.Context(), filepath.Join(b.TempDir(), "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	h, err := NewDNSHistory(store.DB(), options)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = h.Close(); _ = store.Close() })
	settings := DefaultDNSHistorySettings()
	settings.Enabled, settings.MaxRecords = enabled, DNSHistoryMaxMaxRecords
	if _, err := h.SaveSettings(b.Context(), settings); err != nil {
		b.Fatal(err)
	}
	return h
}

// benchAgent answers every query from the resolver cache, the DNS hot path.
func benchAgent(b *testing.B, observer netapi.DNSObserver) (netapi.DNSAgent, []byte) {
	b.Helper()
	upstream := resolver.NewClient(resolver.Config{Name: "bench", Type: "udp"}, resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		return &dns.Msg{ID: req.ID, Response: true, Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 600}, Addr: netip.MustParseAddr("192.0.2.1")}}}, nil
	}))
	if _, err := upstream.Raw(b.Context(), netapi.DNSQuestion{Name: "bench.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}); err != nil {
		b.Fatal(err)
	}
	var agent netapi.DNSAgent
	if observer != nil {
		agent = server.NewServer("", upstream, observer)
	} else {
		agent = server.NewServer("", upstream)
	}
	b.Cleanup(func() { _ = agent.Close(); _ = upstream.Close() })
	q := netapi.NewDNSMsg(netapi.DNSQuestion{Name: "bench.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	q.Response = false
	if err := q.Pack(); err != nil {
		b.Fatal(err)
	}
	return agent, q.Data
}

// serve runs one cached request the way the local UDP listener does: the
// observer, if any, starts the trace and the agent finishes it.
func serve(b *testing.B, agent netapi.DNSAgent, observer netapi.DNSObserver, query []byte) {
	var trace *netapi.DNSTrace
	if observer != nil {
		trace = observer.BeginDNS("udp", netapi.DNSSourceLocal)
	}
	packet := netapi.NewPacket(nil, nil, pool.Clone(query), nil)
	err := agent.DoDatagram(context.Background(), &netapi.DNSRawRequest{Question: packet, Trace: trace, WriteBack: func(p []byte) error { trace.AddSent(len(p)); return nil }})
	packet.DecRef()
	if err != nil {
		b.Fatal(err)
	}
}

func reportRecorder(b *testing.B, h *DNSHistory) {
	if h == nil {
		return
	}
	s := h.Status()
	b.ReportMetric(float64(s.RecordsDropped), "dropped")
	b.ReportMetric(float64(s.Persisted), "persisted")
}

func BenchmarkDNSHistory(b *testing.B) {
	b.Run("no_observer", func(b *testing.B) {
		agent, query := benchAgent(b, nil)
		b.ReportAllocs()
		for b.Loop() {
			serve(b, agent, nil, query)
		}
	})
	b.Run("disabled", func(b *testing.B) {
		h := benchHistory(b, DNSHistoryOptions{}, false)
		agent, query := benchAgent(b, h)
		b.ReportAllocs()
		for b.Loop() {
			serve(b, agent, h, query)
		}
		reportRecorder(b, h)
	})
	b.Run("enabled", func(b *testing.B) {
		h := benchHistory(b, DNSHistoryOptions{QueueSize: 1 << 16}, true)
		agent, query := benchAgent(b, h)
		b.ReportAllocs()
		for b.Loop() {
			serve(b, agent, h, query)
		}
		b.StopTimer()
		_ = h.Close()
		reportRecorder(b, h)
	})
	b.Run("queue", func(b *testing.B) {
		// Trace bookkeeping and the non-blocking enqueue alone.
		h := benchHistory(b, DNSHistoryOptions{QueueSize: 1 << 16}, true)
		msg := &dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: "bench.example.", Class: dns.ClassINET}}}}
		b.ReportAllocs()
		for b.Loop() {
			trace := h.BeginDNS("udp", netapi.DNSSourceHijack)
			trace.SetQuery(msg, 33)
			trace.SetResponse(msg)
			trace.SetDelivery(49, false)
			trace.AddSent(49)
			trace.Finish(nil)
		}
		b.StopTimer()
		_ = h.Close()
		reportRecorder(b, h)
	})
	b.Run("queue_full", func(b *testing.B) {
		gate := make(chan struct{})
		h := benchHistory(b, DNSHistoryOptions{QueueSize: 1, BatchSize: 1, writeGate: gate}, true)
		agent, query := benchAgent(b, h)
		b.ReportAllocs()
		for b.Loop() {
			serve(b, agent, h, query)
		}
		b.StopTimer()
		reportRecorder(b, h)
		close(gate)
	})
	b.Run("batch_write", func(b *testing.B) {
		h := benchHistory(b, DNSHistoryOptions{}, true)
		batch := make([]*netapi.DNSTraceData, 256)
		for i := range batch {
			batch[i] = sampleTrace(i, time.Now())
		}
		b.ReportAllocs()
		start := time.Now()
		for b.Loop() {
			if err := h.write(batch); err != nil {
				b.Fatal(err)
			}
		}
		elapsed := time.Since(start)
		b.ReportMetric(float64(b.N*len(batch))/elapsed.Seconds(), "records/s")
		b.ReportMetric(float64(elapsed.Microseconds())/float64(b.N), "µs/flush")
	})
	b.Run("high_concurrency", func(b *testing.B) {
		h := benchHistory(b, DNSHistoryOptions{}, true)
		agent, query := benchAgent(b, h)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		b.ReportAllocs()
		b.SetParallelism(8)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				serve(b, agent, h, query)
			}
		})
		b.StopTimer()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(int64(after.HeapInuse)-int64(before.HeapInuse))/(1<<20), "heapMiB")
		b.ReportMetric(float64(len(h.queue)), "queued")
		_ = h.Close()
		reportRecorder(b, h)
	})
}
