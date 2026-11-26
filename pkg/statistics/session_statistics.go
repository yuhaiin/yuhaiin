package statistics

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// Session statistics are runtime-only breakdowns for the Connections
// statistics page. They cost a few atomic operations when a connection opens,
// fails or closes, and nothing on the read/write path: per-interval traffic is
// sampled from the running totals whenever an event or a snapshot happens.
const (
	statsHistoryInterval = 10 * time.Second
	statsHistorySlots    = 360 // one hour at statsHistoryInterval
)

// Inclusive upper bounds in milliseconds; a final +Inf bucket follows.
var (
	connectBucketsMS  = []int64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}
	lifetimeBucketsMS = []int64{1_000, 5_000, 10_000, 30_000, 60_000, 300_000, 600_000, 1_800_000, 3_600_000}
)

type failureKind uint8

const (
	failureOther failureKind = iota
	failureTimeout
	failureRefused
	failureReset
	failureUnreachable
	failureDNS
	failureBlocked
	failureCanceled
	failureKindCount
)

var failureKindNames = [failureKindCount]string{
	failureOther:       "other",
	failureTimeout:     "timeout",
	failureRefused:     "refused",
	failureReset:       "reset",
	failureUnreachable: "unreachable",
	failureDNS:         "dns",
	failureBlocked:     "blocked",
	failureCanceled:    "canceled",
}

// classifyFailure maps a dial error to a coarse, user-facing cause. Policy
// blocks are checked first: an outer dial error must not hide them.
func classifyFailure(err error) failureKind {
	switch {
	case err == nil:
		return failureOther
	case netapi.IsBlockError(err):
		return failureBlocked
	case errors.Is(err, context.Canceled):
		return failureCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return failureTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return failureRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED), errors.Is(err, syscall.EPIPE):
		return failureReset
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.EHOSTDOWN):
		return failureUnreachable
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return failureDNS
	}
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return failureTimeout
	}
	return failureOther
}

func bucketIndex(bounds []int64, d time.Duration) int {
	ms := d.Milliseconds()
	for i, bound := range bounds {
		if ms <= bound {
			return i
		}
	}
	return len(bounds)
}

type statsSlot struct {
	slot        int64
	opened      uint64
	failed      uint64
	closed      uint64
	activeStart uint64
	activePeak  uint64
	activeEnd   uint64
	connectNS   uint64
	download    uint64
	upload      uint64
}

type sessionStatistics struct {
	cache *TotalCache

	since    atomic.Int64
	opened   atomic.Uint64
	failed   atomic.Uint64
	closed   atomic.Uint64
	active   atomic.Int64
	connect  [11]atomic.Uint64
	lifetime [10]atomic.Uint64
	failures [failureKindCount]atomic.Uint64

	mu           sync.Mutex
	history      [statsHistorySlots]statsSlot
	baseDownload uint64 // running totals at the last reset
	baseUpload   uint64
	sampleSlot   int64 // slot of the last traffic sample; 0 before the first
	sampleDown   uint64
	sampleUp     uint64
}

func newSessionStatistics(cache *TotalCache, now time.Time) *sessionStatistics {
	s := &sessionStatistics{cache: cache}
	s.reset(now)
	return s
}

func (s *sessionStatistics) totals() (download, upload uint64) {
	if s.cache == nil {
		return 0, 0
	}
	return s.cache.LoadRunningDownload(), s.cache.LoadRunningUpload()
}

// reset clears every breakdown. Open connections stay counted as active and
// their remaining traffic is attributed to the new period.
func (s *sessionStatistics) reset(now time.Time) {
	if s == nil {
		return
	}
	s.since.Store(now.UnixMilli())
	s.opened.Store(0)
	s.failed.Store(0)
	s.closed.Store(0)
	for i := range s.connect {
		s.connect[i].Store(0)
	}
	for i := range s.lifetime {
		s.lifetime[i].Store(0)
	}
	for i := range s.failures {
		s.failures[i].Store(0)
	}
	download, upload := s.totals()
	s.mu.Lock()
	s.history = [statsHistorySlots]statsSlot{}
	s.baseDownload, s.baseUpload = download, upload
	s.sampleSlot, s.sampleDown, s.sampleUp = now.UnixNano()/int64(statsHistoryInterval), download, upload
	s.mu.Unlock()
}

// slotLocked returns the ring entry for slot, starting it from the current
// number of active connections when it is new.
func (s *sessionStatistics) slotLocked(slot int64, active uint64) *statsSlot {
	h := &s.history[((slot%statsHistorySlots)+statsHistorySlots)%statsHistorySlots]
	if h.slot != slot {
		*h = statsSlot{slot: slot, activeStart: active, activePeak: active, activeEnd: active}
	}
	return h
}

// sampleLocked attributes the traffic since the previous sample to the slots
// in between. Gaps without events are filled evenly, so a long transfer with
// no new connections still draws a continuous line instead of one spike.
func (s *sessionStatistics) sampleLocked(slot int64, download, upload uint64, active uint64) {
	if s.sampleSlot == 0 || download < s.sampleDown || upload < s.sampleUp {
		s.sampleSlot, s.sampleDown, s.sampleUp = slot, download, upload
		return
	}
	deltaDown, deltaUp := download-s.sampleDown, upload-s.sampleUp
	s.sampleDown, s.sampleUp = download, upload
	first := s.sampleSlot + 1
	if first > slot {
		first = slot
	}
	if oldest := slot - statsHistorySlots + 1; first < oldest {
		// Traffic older than the window is dropped from the history only.
		span := uint64(slot - s.sampleSlot)
		keep := uint64(statsHistorySlots)
		deltaDown, deltaUp = deltaDown/span*keep, deltaUp/span*keep
		first = oldest
	}
	s.sampleSlot = slot
	if deltaDown == 0 && deltaUp == 0 {
		return
	}
	span := uint64(slot - first + 1)
	for current := first; current <= slot; current++ {
		h := s.slotLocked(current, active)
		partDown, partUp := deltaDown/span, deltaUp/span
		if current == slot { // the remainder lands in the newest slot
			partDown, partUp = deltaDown-partDown*(span-1), deltaUp-partUp*(span-1)
		}
		h.download += partDown
		h.upload += partUp
	}
}

func (s *sessionStatistics) record(now time.Time, update func(*statsSlot, uint64)) {
	download, upload := s.totals()
	slot := now.UnixNano() / int64(statsHistoryInterval)
	s.mu.Lock()
	defer s.mu.Unlock()
	active := uint64(max(s.active.Load(), 0))
	s.sampleLocked(slot, download, upload, active)
	h := s.slotLocked(slot, active)
	if update != nil {
		update(h, active)
	}
	h.activePeak = max(h.activePeak, active)
	h.activeEnd = active
}

func (s *sessionStatistics) connOpened(connectTime time.Duration, now time.Time) {
	if s == nil {
		return
	}
	s.opened.Add(1)
	s.active.Add(1)
	s.connect[bucketIndex(connectBucketsMS, connectTime)].Add(1)
	s.record(now, func(h *statsSlot, _ uint64) {
		h.opened++
		h.connectNS += uint64(max(connectTime, 0))
	})
}

func (s *sessionStatistics) connFailed(err error, now time.Time) {
	if s == nil {
		return
	}
	s.failed.Add(1)
	s.failures[classifyFailure(err)].Add(1)
	s.record(now, func(h *statsSlot, _ uint64) { h.failed++ })
}

func (s *sessionStatistics) connClosed(lifetime time.Duration, now time.Time) {
	if s == nil {
		return
	}
	s.active.Add(-1)
	// A connection opened before a reset still closes after it; count it so
	// closed + active stays consistent with what the page shows.
	s.closed.Add(1)
	s.lifetime[bucketIndex(lifetimeBucketsMS, lifetime)].Add(1)
	s.record(now, func(h *statsSlot, _ uint64) { h.closed++ })
}

func bucketsSnapshot(bounds []int64, counts []atomic.Uint64) []contractconnection.StatisticsBucket {
	result := make([]contractconnection.StatisticsBucket, 0, len(counts))
	for i := range counts {
		bound := int64(0)
		if i < len(bounds) {
			bound = bounds[i]
		}
		result = append(result, contractconnection.StatisticsBucket{LeMS: bound, Count: counts[i].Load()})
	}
	return result
}

func (s *sessionStatistics) snapshot(activeTCP, activeUDP int, now time.Time) contractconnection.Statistics {
	if s == nil {
		return contractconnection.Statistics{
			ConnectTime: []contractconnection.StatisticsBucket{},
			Lifetime:    []contractconnection.StatisticsBucket{},
			Failures:    []contractconnection.FailureKind{},
		}
	}
	// Close the current traffic interval so the newest point is up to date.
	s.record(now, nil)

	result := contractconnection.Statistics{
		SinceUnixMS: s.since.Load(),
		Active:      activeTCP + activeUDP,
		ActiveTCP:   activeTCP,
		ActiveUDP:   activeUDP,
		Opened:      s.opened.Load(),
		Failed:      s.failed.Load(),
		Closed:      s.closed.Load(),
		ConnectTime: bucketsSnapshot(connectBucketsMS, s.connect[:]),
		Lifetime:    bucketsSnapshot(lifetimeBucketsMS, s.lifetime[:]),
		Failures:    make([]contractconnection.FailureKind, 0, failureKindCount),
	}
	for kind := range failureKindCount {
		if count := s.failures[kind].Load(); count > 0 {
			result.Failures = append(result.Failures, contractconnection.FailureKind{Kind: failureKindNames[kind], Count: count})
		}
	}

	current := now.UnixNano() / int64(statsHistoryInterval)
	history := contractconnection.StatisticsHistory{
		IntervalMS: statsHistoryInterval.Milliseconds(),
		EndUnixMS:  (current + 1) * statsHistoryInterval.Milliseconds(),
		Opened:     make([]uint64, statsHistorySlots),
		Failed:     make([]uint64, statsHistorySlots),
		Closed:     make([]uint64, statsHistorySlots),
		Active:     make([]uint64, statsHistorySlots),
		ConnectNS:  make([]uint64, statsHistorySlots),
		Download:   make([]uint64, statsHistorySlots),
		Upload:     make([]uint64, statsHistorySlots),
	}
	download, upload := s.totals()
	s.mu.Lock()
	result.Download = download - min(download, s.baseDownload)
	result.Upload = upload - min(upload, s.baseUpload)
	since := s.since.Load() * int64(time.Millisecond) / int64(statsHistoryInterval)
	carry, known := uint64(0), false
	for i := range statsHistorySlots {
		slot := current - int64(statsHistorySlots-1-i)
		h := s.history[((slot%statsHistorySlots)+statsHistorySlots)%statsHistorySlots]
		if h.slot != slot {
			// Untouched intervals keep the gauge of the last known one. Before
			// the first event in the window the earliest known start is used.
			if !known {
				carry = s.firstActiveLocked(slot, current)
				known = true
			}
			if slot >= since {
				history.Active[i] = carry
			}
			continue
		}
		known = true
		carry = h.activeEnd
		history.Opened[i] = h.opened
		history.Failed[i] = h.failed
		history.Closed[i] = h.closed
		history.Active[i] = h.activePeak
		history.ConnectNS[i] = h.connectNS
		history.Download[i] = h.download
		history.Upload[i] = h.upload
	}
	s.mu.Unlock()
	result.History = history
	return result
}

// firstActiveLocked returns the active count at the start of the first
// recorded slot after from, or the current count when none is recorded.
func (s *sessionStatistics) firstActiveLocked(from, current int64) uint64 {
	for slot := from + 1; slot <= current; slot++ {
		h := s.history[((slot%statsHistorySlots)+statsHistorySlots)%statsHistorySlots]
		if h.slot == slot {
			return h.activeStart
		}
	}
	return uint64(max(s.active.Load(), 0))
}

// Statistics reports the runtime breakdown since the process started or the
// last ResetStatistics.
func (c *Connections) Statistics(context.Context) (contractconnection.Statistics, error) {
	var tcp, udp int
	c.connStore.Range(func(_ uint64, value connection) bool {
		if _, ok := value.(*packetConn); ok {
			udp++
		} else {
			tcp++
		}
		return true
	})
	return c.stats.snapshot(tcp, udp, time.Now()), nil
}

// ResetStatistics clears the runtime breakdown. Persisted totals, traffic
// history and telemetry are left untouched.
func (c *Connections) ResetStatistics(context.Context) error {
	c.stats.reset(time.Now())
	return nil
}
