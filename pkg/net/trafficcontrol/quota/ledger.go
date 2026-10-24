package quota

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

type window struct {
	mu                         sync.Mutex
	record                     Record
	recovery, inflight, wanted Amounts
	pending                    bool
	ready                      chan struct{}
	exhausted                  chan struct{}
	version, savedVersion      uint64
	published                  [3]atomic.Uint64
	terminationNotified        bool
	retired                    atomic.Bool
}

type Ledger struct {
	mu                        sync.Mutex // Control/background paths only; never taken for traffic.
	windows                   map[Key]*window
	store                     Store
	requests                  chan *window
	slots                     chan struct{}
	events                    chan Event
	terminations              chan struct{}
	maintenance               chan maintenanceRequest
	ctx                       context.Context
	cancel                    context.CancelFunc
	done                      chan struct{}
	closed                    atomic.Bool
	denied, failures, dropped atomic.Uint64
}

func New(store Store) *Ledger {
	ctx, cancel := context.WithCancel(context.Background())
	l := &Ledger{windows: make(map[Key]*window), store: store,
		requests: make(chan *window, 256), slots: make(chan struct{}, 256), events: make(chan Event, 1024), terminations: make(chan struct{}, 1), maintenance: make(chan maintenanceRequest, 1),
		ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go l.run()
	return l
}

type entry struct {
	w     *window
	limit Amounts
	quota resource.Quota
	end   int64
}

// Plan is immutable and shared across sessions. Entries always lock in the same
// total order, including when two users share only some of their group budgets.
type Plan struct {
	ledger  *Ledger
	entries []entry
	common  *Plan
	until   int64
}

func (p *Plan) len() int {
	if p.common == nil {
		return len(p.entries)
	}
	return len(p.entries) + len(p.common.entries)
}

func (p *Plan) at(i int) *entry {
	if i < len(p.entries) {
		return &p.entries[i]
	}
	return &p.common.entries[i-len(p.entries)]
}

// PrepareCredential adds only device-owned quotas to a shared user/group plan.
// Credential keys sort before group/user keys, preserving one lock order without
// copying the shared policy for every device. Composite depth is exactly one.
func (l *Ledger) PrepareCredential(ctx context.Context, common *Plan, bindings []Binding, now time.Time) (*Plan, error) {
	if common != nil {
		if common.ledger != l || common.common != nil || len(common.entries)+len(bindings) > MaxBindings {
			return nil, errors.New("invalid shared quota plan")
		}
		for _, e := range common.entries {
			if e.w.record.Key.Scope == "credential" {
				return nil, errors.New("shared plan contains device quotas")
			}
		}
	}
	for _, b := range bindings {
		if b.Scope != "credential" {
			return nil, errors.New("device plan requires credential quotas")
		}
	}
	p, err := l.Prepare(ctx, bindings, now)
	if err != nil {
		return nil, err
	}
	p.common = common
	if common != nil && common.until != 0 && (p.until == 0 || common.until < p.until) {
		p.until = common.until
	}
	return p, nil
}

// Prepare loads durable state on the control path. Failed preparation cannot
// reset existing state, and a caller must publish only a successful Plan.
func (l *Ledger) Prepare(ctx context.Context, bindings []Binding, now time.Time) (*Plan, error) {
	if len(bindings) > MaxBindings {
		return nil, errors.New("too many quota bindings")
	}
	p := &Plan{ledger: l, entries: make([]entry, 0, len(bindings))}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed.Load() {
		return nil, ErrClosed
	}
	seen := make(map[Key]bool, len(bindings))
	for _, b := range bindings {
		if b.Scope != "user" && b.Scope != "group" && b.Scope != "credential" || b.ScopeID == "" || len(b.ScopeID) > 128 {
			return nil, errors.New("invalid quota owner")
		}
		owner := b.OwnerUserID
		if b.Scope == "user" {
			owner = b.ScopeID
		}
		if b.Scope == "group" {
			owner = ""
		}
		if b.Scope == "credential" && (owner == "" || len(owner) > 128) {
			return nil, errors.New("credential quota requires its immutable owner ID")
		}
		if err := resource.ValidateQuotas([]resource.Quota{b.Quota}); err != nil {
			return nil, err
		}
		start, end, err := Window(b.Quota.Period, now)
		if err != nil {
			return nil, err
		}
		key := Key{Scope: b.Scope, ScopeID: b.ScopeID, QuotaID: b.Quota.ID, Period: b.Quota.Period, StartsAt: start}
		if seen[key] {
			return nil, errors.New("duplicate quota binding")
		}
		seen[key] = true
		w := l.windows[key]
		if w == nil {
			if len(l.windows) >= MaxWindows {
				return nil, errors.New("quota state capacity reached")
			}
			r, err := l.store.Load(ctx, key)
			if err != nil {
				return nil, fmt.Errorf("load quota: %w", err)
			}
			if r.Key != key {
				return nil, errors.New("quota store returned a different key")
			}
			if r.OwnerUserID != "" && r.OwnerUserID != owner {
				return nil, errors.New("quota ownership is inconsistent")
			}
			if r.Denied > 1<<63-1 {
				return nil, errors.New("invalid durable quota denial counter")
			}
			r.OwnerUserID = owner
			w = &window{record: r}
			for i := range r.Measured {
				if r.Measured[i] > r.Charged[i] || r.Charged[i] > 1<<63-1 {
					return nil, errors.New("invalid durable quota counters")
				}
				w.recovery[i] = r.Charged[i] - r.Measured[i]
				w.published[i].Store(r.Charged[i])
			}
			l.windows[key] = w
		}
		if w.record.OwnerUserID != owner {
			return nil, errors.New("quota ownership changed")
		}
		if w.retired.Load() {
			return nil, ErrRetired
		}
		q := b.Quota
		q.Thresholds = slices.Clone(q.Thresholds)
		limit := Amounts{}
		for i, v := range []string{q.Upload, q.Download, q.Combined} {
			limit[i], _ = resource.ParseBytes(v)
		}
		p.entries = append(p.entries, entry{w: w, limit: limit, quota: q, end: end})
		if end != 0 && (p.until == 0 || end < p.until) {
			p.until = end
		}
	}
	slices.SortFunc(p.entries, func(a, b entry) int { return compareKey(a.w.record.Key, b.w.record.Key) })
	return p, nil
}

func compareKey(a, b Key) int {
	return cmp.Or(cmp.Compare(a.Scope, b.Scope), cmp.Compare(a.ScopeID, b.ScopeID), cmp.Compare(a.QuotaID, b.QuotaID), cmp.Compare(a.Period, b.Period), cmp.Compare(a.StartsAt, b.StartsAt))
}

func (p *Plan) lock() {
	for i := range p.len() {
		e := p.at(i)
		e.w.mu.Lock()
	}
}
func (p *Plan) unlock() {
	for i := p.len() - 1; i >= 0; i-- {
		p.at(i).w.mu.Unlock()
	}
}

func (w *window) used(i int) uint64 { return add(w.record.Measured[i], w.recovery[i]) }

// Reservation has one owner. Commit may be called repeatedly/concurrently but
// the object must not be reused until all such calls have finished. Supplying
// caller-owned storage avoids allocating a ticket on each datagram.
type Reservation struct {
	settled   atomic.Bool
	plan      *Plan
	direction Direction
	n         uint64
}

// TryReserve atomically reserves all applicable budgets. Whole datagrams are
// rejected unless they fit; TCP may receive a smaller grant. ErrFunding supplies
// a wake channel for cancellable TCP waits; UDP should drop without waiting.
// No bytes may be forwarded before reservation succeeds.
func (p *Plan) TryReserve(now time.Time, direction Direction, size int, whole bool, ticket *Reservation) (int, <-chan struct{}, error) {
	if direction > Download || size < 0 || ticket == nil {
		return 0, nil, errors.New("invalid quota reservation")
	}
	if p.ledger.closed.Load() {
		return 0, nil, ErrClosed
	}
	if p.until != 0 && now.Unix() >= p.until {
		return 0, nil, ErrExpired
	}
	p.lock()
	defer p.unlock()
	for i := range p.len() {
		if p.at(i).w.retired.Load() {
			return 0, nil, ErrRetired
		}
	}
	n := uint64(min(size, MaxReservationBytes))
	// Even unlimited dimensions use signed SQLite counters. Never wrap a live
	// reservation at the representable boundary.
	for i := range p.len() {
		e := p.at(i)
		for _, i := range [2]int{int(direction), 2} {
			n = min(n, (1<<63-1)-add(e.w.used(i), e.w.inflight[i]))
		}
	}
	for i := range p.len() {
		e := p.at(i)
		if e.quota.Action != "block_new" && e.quota.Action != "terminate" {
			continue
		}
		for _, i := range [2]int{int(direction), 2} {
			if e.limit[i] == 0 {
				continue
			}
			used := add(e.w.used(i), e.w.inflight[i])
			if used >= e.limit[i] {
				n = 0
			} else {
				n = min(n, e.limit[i]-used)
			}
		}
	}
	if size > 0 && (n == 0 || whole && n < uint64(size)) {
		p.ledger.denied.Add(1)
		for i := range p.len() {
			e := p.at(i)
			if e.quota.Action != "block_new" && e.quota.Action != "terminate" {
				continue
			}
			denied := false
			for _, i := range [2]int{int(direction), 2} {
				used := add(e.w.used(i), e.w.inflight[i])
				denied = denied || e.limit[i] != 0 && (used >= e.limit[i] || whole && uint64(size) > e.limit[i]-min(e.limit[i], used))
			}
			if denied {
				e.w.record.Denied = add(e.w.record.Denied, 1)
				e.w.version++
			}
		}
		// In-flight writes may refund credit. Only blocked waiters need a
		// notification channel; successful accounting never allocates one.
		for i := range p.len() {
			e := p.at(i)
			if e.quota.Action != "block_new" && e.quota.Action != "terminate" {
				continue
			}
			for _, i := range [2]int{int(direction), 2} {
				if e.limit[i] != 0 && e.w.inflight[i] > 0 && add(e.w.used(i), e.w.inflight[i]) >= e.limit[i] {
					if e.w.exhausted == nil {
						e.w.exhausted = make(chan struct{})
					}
					return 0, e.w.exhausted, ErrExhausted
				}
			}
		}
		return 0, nil, ErrExhausted
	}
	var wake <-chan struct{}
	var fundingErr error
	for i := range p.len() {
		e := p.at(i)
		for _, i := range [2]int{int(direction), 2} {
			need := add(add(e.w.used(i), e.w.inflight[i]), n)
			if need > e.w.record.Charged[i] {
				ready, err := p.ledger.request(e, direction, n)
				if fundingErr == nil || err != ErrFunding {
					wake, fundingErr = ready, err
				}
				break
			}
		}
	}
	if fundingErr != nil {
		return 0, wake, fundingErr
	}
	for i := range p.len() {
		e := p.at(i)
		e.w.inflight[direction] += n
		e.w.inflight[2] += n
	}
	ticket.plan, ticket.direction, ticket.n = p, direction, n
	ticket.settled.Store(false)
	return int(n), nil, nil
}

// Commit counts only accepted bytes and releases the entire reservation. A
// failed/short write refunds the remainder in every applicable scope.
func (r *Reservation) Commit(accepted int) {
	if r.plan == nil || !r.settled.CompareAndSwap(false, true) {
		return
	}
	if accepted < 0 || uint64(accepted) > r.n {
		panic("quota commit exceeds reservation")
	}
	if r.n == 0 {
		return
	}
	p := r.plan
	p.lock()
	defer p.unlock()
	for i := range p.len() {
		e := p.at(i)
		if accepted > 0 {
			e.w.version++
		}
		for _, i := range [2]int{int(r.direction), 2} {
			w := e.w
			w.inflight[i] -= r.n
			w.record.Measured[i] = add(w.record.Measured[i], uint64(accepted))
			w.published[i].Store(w.used(i))
		}
		if r.n > 0 && e.w.exhausted != nil {
			close(e.w.exhausted)
			e.w.exhausted = nil
		}
		p.ledger.alert(e)
		p.ledger.notifyTermination(e)
	}
}

func (l *Ledger) alert(e *entry) {
	for _, threshold := range e.quota.Thresholds {
		word, bit := threshold/64, uint(threshold%64)
		if e.w.record.Alerts[word]&(1<<bit) != 0 {
			continue
		}
		crossed := false
		for i, limit := range e.limit {
			// ceil(limit * threshold / 100), without overflowing int64.
			at := limit/100*uint64(threshold) + (limit%100*uint64(threshold)+99)/100
			crossed = crossed || limit != 0 && e.w.used(i) >= at
		}
		if !crossed {
			continue
		}
		e.w.record.Alerts[word] |= 1 << bit
		e.w.version++
		select {
		case l.events <- Event{OwnerUserID: e.w.record.OwnerUserID, Key: e.w.record.Key, At: time.Now().Unix(), Threshold: threshold}:
		default:
			l.dropped.Add(1)
		}
	}
}

func decimal(n uint64) string { return strconv.FormatUint(n, 10) }

func (p *Plan) Usage() []resource.QuotaUsage {
	p.lock()
	defer p.unlock()
	result := make([]resource.QuotaUsage, 0, p.len())
	for i := range p.len() {
		e := p.at(i)
		var used, remaining Amounts
		exceeded := false
		for i, limit := range e.limit {
			used[i] = e.w.used(i)
			if limit != 0 {
				remaining[i] = limit - min(limit, add(used[i], e.w.inflight[i]))
				exceeded = exceeded || used[i] >= limit
			}
		}
		k := e.w.record.Key
		result = append(result, resource.QuotaUsage{QuotaID: k.QuotaID, Scope: k.Scope, ScopeID: k.ScopeID, Period: k.Period, StartsAt: k.StartsAt, ResetsAt: e.end,
			Measured: bytesContract(e.w.record.Measured), RecoveryCharge: bytesContract(e.w.recovery), Used: bytesContract(used), Remaining: bytesContract(remaining), Limit: bytesContract(e.limit), Action: e.quota.Action, Exceeded: exceeded, Thresholds: slices.Clone(e.quota.Thresholds), Violations: decimal(e.w.record.Denied)})
	}
	return result
}
