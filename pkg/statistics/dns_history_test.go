package statistics

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/dnshistory"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func openDNSHistory(t *testing.T, options DNSHistoryOptions) (*DNSHistory, *storagesqlite.Store) {
	t.Helper()
	store, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h, err := NewDNSHistory(store.DB(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h, store
}

func sampleTrace(i int, at time.Time) *netapi.DNSTraceData {
	d := &netapi.DNSTraceData{
		CreatedAt: at, Duration: time.Duration(i+1) * time.Millisecond,
		Transport: "udp", SourceType: netapi.DNSSourceHijack, ClientIP: "10.0.0.2", ClientPort: 5353,
		InboundID: "tun", InboundName: "TUN", ProcessName: "/usr/bin/curl",
		Domain: fmt.Sprintf("host%d.example.com.", i), QType: dns.TypeA, QClass: dns.ClassINET, TransactionID: uint16(i),
		Resolver: "r1", ResolverLabel: "Primary", Server: "192.0.2.53:53", ServerType: "udp",
		CacheStatus: netapi.DNSCacheMiss, Source: netapi.DNSResolutionUpstream, Outcome: netapi.DNSOutcomeSuccess,
		FakeIPReason: "disabled", FakeIPAllocation: "not_requested", RequestSize: 40, ResponseSize: 56, SentBytes: 56,
		Response: &netapi.DNSResponseSnapshot{Rcode: dns.RcodeSuccess, RecursionAvailable: true,
			Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: fmt.Sprintf("host%d.example.com.", i), Class: dns.ClassINET, TTL: 30}, Addr: netip.MustParseAddr("203.0.113.1")}}},
		Attempts: []netapi.DNSAttempt{{Resolver: "Primary", Transport: "udp", Duration: time.Millisecond, Result: "success", Rcode: "NOERROR"}},
	}
	return d
}

func waitPersisted(t *testing.T, h *DNSHistory, n uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.persisted.Load()+h.persistErrors.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("persisted %d, errors %d, want %d", h.persisted.Load(), h.persistErrors.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDNSHistoryBatchPersistAndDetail(t *testing.T) {
	h, _ := openDNSHistory(t, DNSHistoryOptions{BatchSize: 8, FlushInterval: 10 * time.Millisecond})
	d := sampleTrace(1, time.Now())
	d.FakeIPRequested, d.FakeIPReturned, d.FakeIPv4, d.FakeIPPoolIPv4, d.FakeIPReason, d.FakeIPAllocation = true, true, "198.18.0.9", "198.18.0.0/15", "force_fakeip", "allocated"
	d.ForceFakeIP, d.Source, d.GroupIDs = true, netapi.DNSResolutionFakeIP, []string{"g1"}
	d.Response.Answer = append(d.Response.Answer, &dns.TXT{Hdr: dns.Header{Name: "host1.example.com.", Class: dns.ClassINET, TTL: 5}, Txt: []string{strings.Repeat("x", 600)}})
	for range 3 {
		h.enqueue(d)
	}
	waitPersisted(t, h, 3)
	page, err := h.List(t.Context(), contract.ListRequest{})
	if err != nil || page.Total != 3 || len(page.Items) != 3 {
		t.Fatalf("list = %+v %v", page, err)
	}
	item := page.Items[0]
	if item.Domain != "host1.example.com" || item.QueryType != "A" || item.Rcode != "NOERROR" || !item.FakeIP.Returned || item.AnswerSummary == "" || item.Answer != nil {
		t.Fatalf("summary item = %+v", item)
	}
	record, err := h.Get(t.Context(), item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Answer) != 2 || record.Answer[1].Type != "TXT" || !record.Answer[1].DataTruncated || len(record.Answer[1].Data) != dnsHistoryMaxRDATA {
		t.Fatalf("answer = %+v", record.Answer)
	}
	if record.FakeIP.PoolIPv4 != "198.18.0.0/15" || !record.FakeIP.Force || record.FakeIP.Allocation != "allocated" || len(record.GroupIDs) != 1 {
		t.Fatalf("fakeip detail = %+v", record.FakeIP)
	}
	if record.Flags == nil || !record.Flags.RA || record.Details == nil || len(record.Details.Attempts) != 1 {
		t.Fatalf("flags/details = %+v %+v", record.Flags, record.Details)
	}
	if _, err := h.Get(t.Context(), 99999); !errors.Is(err, ErrDNSHistoryNotFound) {
		t.Fatalf("missing record err = %v", err)
	}
}

func TestDNSHistoryPaginationWithEqualTimestamps(t *testing.T) {
	h, _ := openDNSHistory(t, DNSHistoryOptions{})
	at := time.Now()
	var batch []*netapi.DNSTraceData
	for i := range 25 {
		batch = append(batch, sampleTrace(i, at))
	}
	if err := h.write(batch); err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := h.List(t.Context(), contract.ListRequest{Limit: 10, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if page.Total != 25 {
			t.Fatalf("total = %d", page.Total)
		}
		for _, item := range page.Items {
			if seen[item.ID] {
				t.Fatalf("duplicate id %d", item.ID)
			}
			seen[item.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 25 || pages != 3 {
		t.Fatalf("seen %d records in %d pages", len(seen), pages)
	}
	// Numbered pages over the same equal timestamps match the cursor walk.
	numbered := map[int64]bool{}
	for page := 1; page <= 3; page++ {
		result, err := h.List(t.Context(), contract.ListRequest{Limit: 10, Page: page})
		if err != nil || result.Page != page || result.Total != 25 {
			t.Fatalf("page %d = %+v %v", page, result, err)
		}
		for _, item := range result.Items {
			if numbered[item.ID] {
				t.Fatalf("page %d repeats %d", page, item.ID)
			}
			numbered[item.ID] = true
		}
	}
	if len(numbered) != 25 {
		t.Fatalf("numbered pages saw %d records", len(numbered))
	}
	for _, bad := range []contract.ListRequest{{Page: -1}, {Page: dnsHistoryMaxPage + 1}, {Page: 2, Cursor: "a.1"}} {
		if _, err := h.List(t.Context(), bad); !errors.Is(err, ErrDNSHistoryBadRequest) {
			t.Fatalf("%+v: err = %v", bad, err)
		}
	}
	if _, err := h.List(t.Context(), contract.ListRequest{Cursor: "bogus"}); !errors.Is(err, ErrDNSHistoryBadRequest) {
		t.Fatalf("bad cursor err = %v", err)
	}
	if page, _ := h.List(t.Context(), contract.ListRequest{Limit: 10_000}); page.Limit != dnsHistoryMaxPageSize {
		t.Fatalf("limit not capped: %d", page.Limit)
	}
}

func TestDNSHistoryFilters(t *testing.T) {
	h, _ := openDNSHistory(t, DNSHistoryOptions{})
	now := time.Now()
	records := []*netapi.DNSTraceData{sampleTrace(0, now.Add(-time.Hour)), sampleTrace(1, now), sampleTrace(2, now), sampleTrace(3, now)}
	records[0].Domain = "example.com."
	records[1].Domain, records[1].QType, records[1].Transport, records[1].SourceType = "api.example.com.", dns.TypeAAAA, "tcp", netapi.DNSSourceLocal
	records[2].Domain, records[2].Outcome, records[2].Response, records[2].FailureStage = "slow.other.net.", netapi.DNSOutcomeTimeout, nil, netapi.DNSStageUpstream
	records[3].Domain, records[3].FakeIPReturned, records[3].ProcessName, records[3].InboundID = "fake.other.net.", true, "/opt/Firefox", "lan"
	records[3].Response.Rcode = dns.RcodeNameError
	if err := h.write(records); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		req  contract.ListRequest
		want int
	}{
		{"domain suffix", contract.ListRequest{Domain: "example.com"}, 2},
		{"domain wildcard", contract.ListRequest{Domain: "*.example.com"}, 2},
		{"no partial label", contract.ListRequest{Domain: "ample.com"}, 0},
		{"query substring", contract.ListRequest{Query: "OTHER"}, 2},
		{"qtype", contract.ListRequest{QueryType: "aaaa"}, 1},
		{"transport", contract.ListRequest{Transport: "tcp"}, 1},
		{"source", contract.ListRequest{SourceType: netapi.DNSSourceHijack}, 3},
		{"inbound", contract.ListRequest{InboundID: "lan"}, 1},
		{"process", contract.ListRequest{Process: "firefox"}, 1},
		{"resolver label", contract.ListRequest{Resolver: "Primary"}, 4},
		{"server", contract.ListRequest{Server: "192.0.2.53:53"}, 4},
		{"outcomes", contract.ListRequest{Outcome: "timeout,servfail"}, 1},
		{"rcode", contract.ListRequest{Rcode: "NXDOMAIN"}, 1},
		{"fakeip", contract.ListRequest{FakeIPOnly: true}, 1},
		{"time range", contract.ListRequest{From: now.Add(-time.Minute).UnixMilli(), To: now.Add(time.Minute).UnixMilli()}, 3},
		{"combined", contract.ListRequest{Domain: "other.net", FakeIPOnly: true}, 1},
	}
	for _, c := range cases {
		page, err := h.List(t.Context(), c.req)
		if err != nil || page.Total != c.want || len(page.Items) != c.want {
			t.Errorf("%s: total=%d items=%d err=%v, want %d", c.name, page.Total, len(page.Items), err, c.want)
		}
	}
	for _, bad := range []contract.ListRequest{{QueryType: "NOPE"}, {Outcome: "great"}, {Transport: "quic"}, {Rcode: "WAT"}, {From: 5, To: 1}, {Domain: strings.Repeat("a", 300)}, {Query: "x' OR 1=1 --"}} {
		_, err := h.List(t.Context(), bad)
		if bad.Query != "" {
			if err != nil {
				t.Errorf("parameterized query rejected: %v", err)
			}
			continue
		}
		if !errors.Is(err, ErrDNSHistoryBadRequest) {
			t.Errorf("%+v: err = %v", bad, err)
		}
	}
	stats, err := h.Stats(t.Context(), contract.StatsRequest{From: now.Add(-2 * time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 4 || stats.Success != 3 || stats.Failed != 1 || stats.Timeout != 1 || stats.FakeIP != 1 || stats.CacheMisses != 4 || stats.AvgLatencyNs <= 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestDNSHistoryQueriesUseIndexes(t *testing.T) {
	_, store := openDNSHistory(t, DNSHistoryOptions{})
	for _, c := range []struct {
		req   contract.ListRequest
		index string
	}{
		{contract.ListRequest{}, "dns_query_history_created"},
		{contract.ListRequest{Domain: "example.com"}, "dns_query_history_domain"},
		{contract.ListRequest{Outcome: "timeout"}, "dns_query_history_outcome"},
		{contract.ListRequest{SourceType: netapi.DNSSourceLocal}, "dns_query_history_source"},
	} {
		w, err := buildDNSHistoryFilter(c.req)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := store.DB().QueryContext(t.Context(), `EXPLAIN QUERY PLAN SELECT id FROM dns_query_history`+w.sql()+` ORDER BY created_at DESC, id DESC LIMIT 50`, w.args...)
		if err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan.WriteString(detail + "; ")
		}
		_ = rows.Close()
		if !strings.Contains(plan.String(), c.index) {
			t.Errorf("%+v plan = %s", c.req, plan.String())
		}
	}
}

func TestDNSHistoryRetentionAndClear(t *testing.T) {
	h, store := openDNSHistory(t, DNSHistoryOptions{})
	if _, err := h.SaveSettings(t.Context(), contract.Settings{Enabled: true, RetentionHours: 72, MaxRecords: 100}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var batch []*netapi.DNSTraceData
	batch = append(batch, sampleTrace(0, now.Add(-4*24*time.Hour)))
	for i := range 150 {
		batch = append(batch, sampleTrace(i+1, now.Add(time.Duration(i)*time.Millisecond)))
	}
	if err := h.write(batch); err != nil {
		t.Fatal(err)
	}
	h.pruneNow()
	var count int
	var oldest int64
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*), MIN(created_at) FROM dns_query_history`).Scan(&count, &oldest); err != nil {
		t.Fatal(err)
	}
	if count != 100 || oldest < now.Add(50*time.Millisecond).UnixNano() {
		t.Fatalf("after prune count=%d oldest=%v", count, time.Unix(0, oldest))
	}
	cleared, err := h.Clear(t.Context())
	if err != nil || cleared.Deleted != 100 {
		t.Fatalf("clear = %+v %v", cleared, err)
	}
}

func TestDNSHistorySettings(t *testing.T) {
	h, store := openDNSHistory(t, DNSHistoryOptions{})
	if got := h.Settings(); got != DefaultDNSHistorySettings() || h.BeginDNS("udp", netapi.DNSSourceLocal) == nil {
		t.Fatalf("defaults = %+v", got)
	}
	for _, bad := range []contract.Settings{{RetentionHours: 0, MaxRecords: 1000}, {RetentionHours: 1, MaxRecords: 1}, {RetentionHours: 10_000, MaxRecords: 1000}} {
		if _, err := h.SaveSettings(t.Context(), bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	saved := contract.Settings{Enabled: false, RetentionHours: 12, MaxRecords: 500}
	if _, err := h.SaveSettings(t.Context(), saved); err != nil {
		t.Fatal(err)
	}
	if h.BeginDNS("udp", netapi.DNSSourceLocal) != nil {
		t.Fatal("disabled history started a trace")
	}
	reopened, err := NewDNSHistory(store.DB(), DNSHistoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Settings() != saved || reopened.Status().Enabled {
		t.Fatalf("persisted settings = %+v", reopened.Settings())
	}
}

func TestDNSHistoryQueueFullNeverBlocks(t *testing.T) {
	gate := make(chan struct{})
	h, _ := openDNSHistory(t, DNSHistoryOptions{QueueSize: 1, BatchSize: 1, FlushInterval: time.Millisecond, writeGate: gate})
	h.enqueue(sampleTrace(0, time.Now()))
	deadline := time.Now().Add(5 * time.Second)
	for len(h.queue) != 0 { // the worker holds the first record in its blocked write
		if time.Now().After(deadline) {
			t.Fatal("worker did not take the first record")
		}
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	for i := range 10 {
		h.enqueue(sampleTrace(i+1, time.Now()))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("enqueue blocked for %v", elapsed)
	}
	if h.dropped.Load() != 9 || len(h.queue) != 1 {
		t.Fatalf("dropped=%d queued=%d", h.dropped.Load(), len(h.queue))
	}
	close(gate)
	waitPersisted(t, h, 2)
	if s := h.Status(); s.RecordsDropped != 9 || s.Persisted != 2 || s.PersistenceErrors != 0 {
		t.Fatalf("status = %+v", s)
	}
}

func TestDNSHistoryPersistenceFailureIsIsolated(t *testing.T) {
	h, store := openDNSHistory(t, DNSHistoryOptions{BatchSize: 4, FlushInterval: time.Millisecond})
	if _, err := store.DB().ExecContext(t.Context(), `DROP TABLE dns_query_history`); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		h.enqueue(sampleTrace(i, time.Now()))
	}
	waitPersisted(t, h, 4)
	s := h.Status()
	if s.PersistenceErrors != 4 || s.Persisted != 0 || s.LastPersistenceError == "" || s.RecordsDropped != 0 {
		t.Fatalf("status = %+v", s)
	}
	// Recording keeps accepting traces; the DNS path is unaffected.
	if h.BeginDNS("udp", netapi.DNSSourceLocal) == nil {
		t.Fatal("persistence failure disabled tracing")
	}
}

func TestDNSHistoryCloseFlushesQueue(t *testing.T) {
	h, store := openDNSHistory(t, DNSHistoryOptions{QueueSize: 512, BatchSize: 64, FlushInterval: time.Hour})
	for i := range 300 {
		h.enqueue(sampleTrace(i, time.Now()))
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM dns_query_history`).Scan(&count); err != nil || count != 300 {
		t.Fatalf("flushed %d, %v", count, err)
	}
	// After Close, completed traces are dropped instead of blocking.
	h.enqueue(sampleTrace(0, time.Now()))
	if h.BeginDNS("udp", netapi.DNSSourceLocal) != nil {
		t.Fatal("closed history started a trace")
	}
}

func TestDNSHistoryBoundedUnderConcurrency(t *testing.T) {
	h, _ := openDNSHistory(t, DNSHistoryOptions{QueueSize: 64, BatchSize: 32, FlushInterval: time.Millisecond})
	const workers, each = 16, 500
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range each {
				trace := h.BeginDNS("udp", netapi.DNSSourceHijack)
				trace.SetQuery(&dns.Msg{Question: []dns.RR{&dns.A{Hdr: dns.Header{Name: fmt.Sprintf("w%d-%d.example.", w, i), Class: dns.ClassINET}}}}, 30)
				trace.Finish(context.Canceled)
				if len(h.queue) > cap(h.queue) {
					t.Error("queue exceeded its capacity")
				}
			}
		})
	}
	wg.Wait()
	_ = h.Close()
	total := h.persisted.Load() + h.dropped.Load() + h.persistErrors.Load()
	if total != workers*each {
		t.Fatalf("accounted %d of %d (persisted %d dropped %d)", total, workers*each, h.persisted.Load(), h.dropped.Load())
	}
}
