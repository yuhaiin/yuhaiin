package gateway

import (
	"cmp"
	"io"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

// Detail statistics are runtime-only breakdowns kept next to the persisted
// lifetime totals. They restart with the process and are cleared together
// with the totals on reset.
const (
	historyInterval = 10 * time.Second
	historySlots    = 360 // one hour at historyInterval
	topHostCapacity = 64
	topHostReported = 20
)

// latencyBucketsMS are inclusive upper bounds; a final +Inf bucket follows.
var latencyBucketsMS = []int64{10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000}

type requestOutcome uint8

const (
	outcomeLocal requestOutcome = iota // respond/redirect/invalid request
	outcomeBlocked
	outcomeForwarded
	outcomeError
)

type historySlot struct {
	slot      int64
	requests  uint64
	blocked   uint64
	forwarded uint64
	errors    uint64
	duration  uint64
	bytesIn   uint64
	bytesOut  uint64
}

type hostCounter struct {
	requests uint64
	blocked  uint64
}

type detailStatistics struct {
	since          atomic.Int64
	active         atomic.Int64
	bytesIn        atomic.Uint64
	bytesOut       atomic.Uint64
	statusClasses  [6]atomic.Uint64 // other, 1xx..5xx
	latency        [12]atomic.Uint64
	ruleHits       sync.Map // rule ID -> *atomic.Uint64
	filterHits     atomic.Uint64
	defaultHits    atomic.Uint64
	mu             sync.Mutex
	history        [historySlots]historySlot
	hosts          map[string]*hostCounter
	evictedRequest uint64
}

func (d *detailStatistics) reset(now time.Time) {
	d.since.Store(now.UnixMilli())
	d.bytesIn.Store(0)
	d.bytesOut.Store(0)
	for i := range d.statusClasses {
		d.statusClasses[i].Store(0)
	}
	for i := range d.latency {
		d.latency[i].Store(0)
	}
	d.ruleHits.Clear()
	d.filterHits.Store(0)
	d.defaultHits.Store(0)
	d.mu.Lock()
	d.history = [historySlots]historySlot{}
	d.hosts = nil
	d.evictedRequest = 0
	d.mu.Unlock()
}

func (d *detailStatistics) ensureSince(now time.Time) {
	d.since.CompareAndSwap(0, now.UnixMilli())
}

func (d *detailStatistics) hitRule(id string) {
	switch id {
	case "":
		d.defaultHits.Add(1)
	default:
		v, ok := d.ruleHits.Load(id)
		if !ok {
			v, _ = d.ruleHits.LoadOrStore(id, new(atomic.Uint64))
		}
		v.(*atomic.Uint64).Add(1)
	}
}

type requestRecord struct {
	start    time.Time
	host     string
	outcome  requestOutcome
	status   int
	bytesIn  atomic.Uint64 // request bodies may be read by the transport goroutine
	bytesOut uint64
}

func latencyBucket(d time.Duration) int {
	ms := d.Milliseconds()
	for i, bound := range latencyBucketsMS {
		if ms <= bound {
			return i
		}
	}
	return len(latencyBucketsMS)
}

func (d *detailStatistics) finish(r *requestRecord, now time.Time) {
	elapsed := now.Sub(r.start)
	class := 0
	if r.status >= 100 && r.status < 600 {
		class = r.status / 100
	}
	d.statusClasses[class].Add(1)
	d.latency[latencyBucket(elapsed)].Add(1)
	bytesIn := r.bytesIn.Load()
	d.bytesIn.Add(bytesIn)
	d.bytesOut.Add(r.bytesOut)

	slot := now.UnixNano() / int64(historyInterval)
	d.mu.Lock()
	defer d.mu.Unlock()
	h := &d.history[slot%historySlots]
	if h.slot != slot {
		*h = historySlot{slot: slot}
	}
	h.requests++
	h.duration += uint64(elapsed)
	h.bytesIn += bytesIn
	h.bytesOut += r.bytesOut
	switch r.outcome {
	case outcomeBlocked:
		h.blocked++
	case outcomeForwarded:
		h.forwarded++
	case outcomeError:
		h.errors++
	}
	if r.host != "" {
		d.countHostLocked(r.host, r.outcome == outcomeBlocked)
	}
}

// countHostLocked keeps a bounded space-saving summary: when full, the least
// requested host is replaced and the newcomer inherits its count, so heavy
// hitters are never under-counted and memory stays fixed.
func (d *detailStatistics) countHostLocked(host string, blocked bool) {
	if d.hosts == nil {
		d.hosts = make(map[string]*hostCounter, topHostCapacity)
	}
	c := d.hosts[host]
	if c == nil {
		if len(d.hosts) >= topHostCapacity {
			var minHost string
			var minCounter *hostCounter
			for h, v := range d.hosts {
				if minCounter == nil || v.requests < minCounter.requests {
					minHost, minCounter = h, v
				}
			}
			delete(d.hosts, minHost)
			d.evictedRequest = max(d.evictedRequest, minCounter.requests)
			c = &hostCounter{requests: minCounter.requests}
		} else {
			c = &hostCounter{}
		}
		d.hosts[host] = c
	}
	c.requests++
	if blocked {
		c.blocked++
	}
}

func (d *detailStatistics) snapshot(id string, ruleIDs []string, active int64, now time.Time) contract.GatewayStatistics {
	result := contract.GatewayStatistics{
		ID:             id,
		SinceUnixMS:    d.since.Load(),
		ActiveRequests: active,
		BytesIn:        d.bytesIn.Load(),
		BytesOut:       d.bytesOut.Load(),
		StatusClasses:  make([]uint64, len(d.statusClasses)),
		Latency:        make([]contract.LatencyBucket, 0, len(d.latency)),
		Rules:          make([]contract.RuleHits, 0, len(ruleIDs)),
		FilterHits:     d.filterHits.Load(),
		DefaultHits:    d.defaultHits.Load(),
		TopHosts:       []contract.HostHits{},
	}
	for i := range d.statusClasses {
		result.StatusClasses[i] = d.statusClasses[i].Load()
	}
	for i := range d.latency {
		bound := int64(0)
		if i < len(latencyBucketsMS) {
			bound = latencyBucketsMS[i]
		}
		result.Latency = append(result.Latency, contract.LatencyBucket{LeMS: bound, Count: d.latency[i].Load()})
	}
	for _, rid := range ruleIDs {
		hits := uint64(0)
		if v, ok := d.ruleHits.Load(rid); ok {
			hits = v.(*atomic.Uint64).Load()
		}
		result.Rules = append(result.Rules, contract.RuleHits{ID: rid, Hits: hits})
	}

	current := now.UnixNano() / int64(historyInterval)
	history := contract.StatisticsHistory{
		IntervalMS: historyInterval.Milliseconds(),
		EndUnixMS:  (current + 1) * historyInterval.Milliseconds(),
		Requests:   make([]uint64, historySlots),
		Blocked:    make([]uint64, historySlots),
		Forwarded:  make([]uint64, historySlots),
		Errors:     make([]uint64, historySlots),
		DurationNS: make([]uint64, historySlots),
		BytesIn:    make([]uint64, historySlots),
		BytesOut:   make([]uint64, historySlots),
	}
	d.mu.Lock()
	for i := range historySlots {
		slot := current - int64(historySlots-1-i)
		h := d.history[((slot%historySlots)+historySlots)%historySlots]
		if h.slot != slot {
			continue
		}
		history.Requests[i] = h.requests
		history.Blocked[i] = h.blocked
		history.Forwarded[i] = h.forwarded
		history.Errors[i] = h.errors
		history.DurationNS[i] = h.duration
		history.BytesIn[i] = h.bytesIn
		history.BytesOut[i] = h.bytesOut
	}
	for host, c := range d.hosts {
		result.TopHosts = append(result.TopHosts, contract.HostHits{Host: host, Requests: c.requests, Blocked: c.blocked})
	}
	result.HostCountError = d.evictedRequest
	d.mu.Unlock()
	result.History = history
	slices.SortFunc(result.TopHosts, func(a, b contract.HostHits) int {
		return cmp.Or(cmp.Compare(b.Requests, a.Requests), cmp.Compare(a.Host, b.Host))
	})
	if len(result.TopHosts) > topHostReported {
		result.TopHosts = result.TopHosts[:topHostReported]
	}
	return result
}

// Statistics reports the runtime breakdowns of every running Gateway.
func (m *Manager) Statistics() contract.StatisticsReport {
	s := m.current.Load()
	result := contract.StatisticsReport{Gateways: []contract.GatewayStatistics{}}
	if s == nil {
		return result
	}
	now := time.Now()
	for _, config := range s.config.Gateways {
		g := s.gateways[config.ID]
		if g == nil {
			continue
		}
		c := g.engine.Counters
		result.Gateways = append(result.Gateways, c.detail.snapshot(config.ID, config.RuleIDs, c.detail.active.Load(), now))
	}
	return result
}

// statsResponseWriter records the final status and response bytes. Unwrap
// keeps ResponseController (flush, hijack, deadlines) working.
type statsResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  uint64
}

func (w *statsResponseWriter) WriteHeader(status int) {
	if w.status == 0 && (status >= http.StatusOK || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statsResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += uint64(n)
	return n, err
}

func (w *statsResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{w}, r)
}

func (w *statsResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type statsRequestBody struct {
	io.ReadCloser
	bytes *atomic.Uint64
}

func (b statsRequestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes.Add(uint64(n))
	return n, err
}
