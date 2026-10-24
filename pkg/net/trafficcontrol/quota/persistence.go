package quota

import (
	"context"
	"errors"
	"time"
)

// request is called with the window locked. Only the worker publishes funded
// credits, after a successful durable commit. Pending work has a separate bound
// from channel capacity, including when the store remains unavailable.
func (l *Ledger) request(e *entry, direction Direction, n uint64) (<-chan struct{}, error) {
	if l.closed.Load() {
		return nil, ErrClosed
	}
	w := e.w
	needsGrant := false
	for _, i := range [2]int{int(direction), 2} {
		// In-flight bytes are already covered by the current grant. Excluding
		// them here bounds unconfirmed credit to one GrantBytes chunk even
		// when thousands of slow writes hold reservations simultaneously.
		used := w.used(i)
		target := add(used, max(n, GrantBytes))
		if (e.quota.Action == "block_new" || e.quota.Action == "terminate") && e.limit[i] != 0 {
			target = min(target, e.limit[i])
		}
		w.wanted[i] = max(w.wanted[i], target)
		needsGrant = needsGrant || target > w.record.Charged[i]
	}
	if !w.pending {
		if !needsGrant {
			if w.exhausted == nil {
				w.exhausted = make(chan struct{})
			}
			return w.exhausted, ErrFunding
		}
		select {
		case l.slots <- struct{}{}:
		default:
			return nil, ErrBusy
		}
		w.pending = true
		w.ready = make(chan struct{})
		l.requests <- w // A slot guarantees room; the channel is never closed.
	}
	return w.ready, ErrFunding
}

func (l *Ledger) run() {
	defer close(l.done)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	pending := make(map[*window]bool)
	var retryAt time.Time
	nextCheckpoint := time.Now().Add(time.Second)
	for {
		select {
		case <-l.ctx.Done():
			l.mu.Lock()
			for _, w := range l.windows {
				w.mu.Lock()
				if w.pending {
					close(w.ready)
					w.pending = false
					<-l.slots
				}
				if w.exhausted != nil {
					close(w.exhausted)
					w.exhausted = nil
				}
				w.mu.Unlock()
			}
			l.mu.Unlock()
			return
		case w := <-l.requests:
			pending[w] = true
		case request := <-l.maintenance:
			err := l.checkpoint(request.ctx)
			if err == nil {
				err = l.reclaim(request.ctx, time.Now(), false)
			}
			request.done <- err
			continue
		case <-tick.C:
		}
		// Coalesce ready requests without starting another goroutine per quota.
		for len(l.requests) > 0 {
			pending[<-l.requests] = true
		}
		now := time.Now()
		if !now.Before(nextCheckpoint) {
			if err := l.checkpoint(l.ctx); err != nil {
				l.failures.Add(1)
			}
			l.prune(now)
			nextCheckpoint = now.Add(time.Second)
		}
		if len(pending) == 0 || now.Before(retryAt) {
			continue
		}
		windows := make([]*window, 0, len(pending))
		records := make([]Record, 0, len(pending))
		versions := make([]uint64, 0, len(pending))
		for w := range pending {
			w.mu.Lock()
			r := w.record
			for i := range r.Charged {
				r.Charged[i] = max(r.Charged[i], w.wanted[i])
			}
			versions = append(versions, w.version)
			w.mu.Unlock()
			windows = append(windows, w)
			records = append(records, r)
		}
		if err := l.store.Save(l.ctx, records); err != nil {
			l.failures.Add(1)
			retryAt = now.Add(100 * time.Millisecond)
			continue
		}
		for i, w := range windows {
			w.mu.Lock()
			for d := range w.record.Charged {
				w.record.Charged[d] = max(w.record.Charged[d], records[i].Charged[d])
			}
			w.savedVersion = max(w.savedVersion, versions[i])
			close(w.ready)
			w.pending = false
			<-l.slots
			w.mu.Unlock()
			delete(pending, w)
		}
	}
}

func (l *Ledger) checkpoint(ctx context.Context) error {
	l.mu.Lock()
	windows := make([]*window, 0, len(l.windows))
	for _, w := range l.windows {
		windows = append(windows, w)
	}
	l.mu.Unlock()
	// Bounded transactions avoid retaining a second copy of the whole ledger.
	records := make([]Record, 0, 256)
	touched := make([]*window, 0, 256)
	versions := make([]uint64, 0, 256)
	flush := func() error {
		if len(records) == 0 {
			return nil
		}
		if err := l.store.Save(ctx, records); err != nil {
			return err
		}
		for i, w := range touched {
			w.mu.Lock()
			w.savedVersion = max(w.savedVersion, versions[i])
			w.mu.Unlock()
		}
		records, touched, versions = records[:0], touched[:0], versions[:0]
		return nil
	}
	for _, w := range windows {
		w.mu.Lock()
		if w.version != w.savedVersion {
			records = append(records, w.record)
			touched = append(touched, w)
			versions = append(versions, w.version)
		}
		w.mu.Unlock()
		if len(records) == cap(records) {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// RetireUnused is called with the currently configured quota definitions.
// Retired handles stop admitting bytes before their state can be reclaimed.
func (l *Ledger) RetireUnused(keep func(Key) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, w := range l.windows {
		if keep(key) {
			continue
		}
		w.mu.Lock()
		w.retired.Store(true)
		if w.exhausted != nil {
			close(w.exhausted)
			w.exhausted = nil
		}
		w.mu.Unlock()
	}
}

func (l *Ledger) prune(now time.Time) {
	if err := l.reclaim(l.ctx, now, false); err != nil {
		l.failures.Add(1)
	}
}

// The funding worker serializes checkpoint, reclaim and grant writes. Retired
// windows remain locked until the durable return of unused credit succeeds, so
// reactivation cannot load a second live copy with an independent byte balance.
func (l *Ledger) reclaim(ctx context.Context, now time.Time, shutdown bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	requests := make([]Reclaim, 0, 256)
	windows := make([]*window, 0, 256)
	flush := func() error {
		if len(requests) == 0 {
			return nil
		}
		err := l.store.Reclaim(ctx, requests)
		for i, w := range windows {
			if err == nil {
				w.record.Charged = requests[i].Record.Charged
				w.wanted = w.record.Charged
				if !shutdown {
					delete(l.windows, w.record.Key)
				}
			}
			w.mu.Unlock()
		}
		requests, windows = requests[:0], windows[:0]
		return err
	}
	for key, w := range l.windows {
		expired := false
		if key.Period != "lifetime" {
			_, end, err := Window(key.Period, time.Unix(key.StartsAt, 0))
			expired = err == nil && now.Unix() >= end
		}
		if !shutdown && !expired && !w.retired.Load() {
			continue
		}
		w.mu.Lock()
		if !shutdown {
			w.retired.Store(true)
		}
		if w.pending || w.inflight != (Amounts{}) || !shutdown && w.version != w.savedVersion {
			w.mu.Unlock()
			continue
		}
		after := w.record
		maximum := w.record.Charged
		for i := range after.Charged {
			after.Charged[i] = w.used(i)
			maximum[i] = max(maximum[i], w.wanted[i])
		}
		if after.Charged == w.record.Charged && maximum == w.record.Charged {
			if !shutdown {
				delete(l.windows, key)
			}
			w.mu.Unlock()
			continue
		}
		requests = append(requests, Reclaim{Record: after, MaxCharged: maximum})
		windows = append(windows, w)
		if len(requests) == cap(requests) {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// Close stops funding, wakes waiting streams and checkpoints accepted bytes.
// Settled windows return unused grants durably. Windows with outstanding
// reservations retain their conservative credits; owners must settle forwarding
// before closing the ledger for a completely reclaimed clean shutdown.
func (l *Ledger) Close(ctx context.Context) error {
	l.closed.Store(true)
	l.cancel()
	select {
	case <-l.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return errors.Join(l.checkpoint(ctx), l.reclaim(ctx, time.Now(), true))
}

func (l *Ledger) Events() <-chan Event { return l.events }

type maintenanceRequest struct {
	ctx  context.Context
	done chan error
}

// Flush is a control-path barrier for checkpointing and retired-state cleanup.
// The same worker owns every credit write, including this explicit request.
func (l *Ledger) Flush(ctx context.Context) error {
	request := maintenanceRequest{ctx: ctx, done: make(chan error, 1)}
	select {
	case l.maintenance <- request:
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return ErrClosed
	}
	select {
	case err := <-request.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return ErrClosed
	}
}

func (l *Ledger) Terminations() <-chan struct{} { return l.terminations }

func (l *Ledger) Diagnostics() Diagnostics {
	l.mu.Lock()
	n := len(l.windows)
	l.mu.Unlock()
	return Diagnostics{Windows: n, Pending: len(l.slots), Denied: l.denied.Load(), PersistenceFailures: l.failures.Load(), DroppedEvents: l.dropped.Load()}
}
