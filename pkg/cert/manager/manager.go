package manager

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

type Options struct {
	Store       *certificates.Store
	Issue       func(context.Context, contract.Config) (certificates.Material, error)
	RenewalInfo func(context.Context, contract.Config, *tls.Certificate) (RenewalWindow, error)
	Cleanup     func(context.Context) error
	Now         func() time.Time
	// Report receives finite diagnostic codes, never raw CA/provider bodies.
	Report func(string)
}

// Manager owns one cancellable worker and one timer for at most 64 resources.
// SQLite is read only at startup, a due deadline or explicit configuration work.
type Manager struct {
	options             Options
	Cache               *Cache
	mu                  sync.Mutex
	started, closed     bool
	cancel              context.CancelFunc
	activeID            string
	activeCancel        context.CancelFunc
	cleanupRetry        time.Time
	wake                chan struct{}
	wg                  sync.WaitGroup
	eventMu             sync.Mutex
	events              []contract.Event
	eventSequence       uint64
	metricSnapshot      atomic.Pointer[metricSnapshot]
	successes, failures atomic.Uint64
}

func New(options Options) (*Manager, error) {
	if options.Store == nil || options.Issue == nil {
		return nil, errors.New("certificate manager requires storage and an issuer")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	m := &Manager{options: options, Cache: NewCache(options.Store), wake: make(chan struct{}, 1)}
	return m, nil
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.started {
		return errors.New("certificate manager already started or closed")
	}
	if err := m.Cache.Reload(ctx, m.options.Now()); err != nil {
		m.report("certificate_cache_unavailable")
	}
	ctx, m.cancel = context.WithCancel(ctx)
	m.started = true
	m.wg.Go(func() { m.loop(ctx) })
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	m.closed = true
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
	m.wg.Wait()
	return nil
}

func (m *Manager) Wake() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}
func (m *Manager) report(code string) {
	m.eventMu.Lock()
	m.eventSequence++
	if len(m.events) == 64 {
		copy(m.events, m.events[1:])
		m.events = m.events[:63]
	}
	m.events = append(m.events, contract.Event{Sequence: m.eventSequence, At: m.options.Now(), Code: code})
	m.eventMu.Unlock()
	if m.options.Report != nil {
		m.options.Report(code)
	}
}

func (m *Manager) Save(ctx context.Context, c contract.Config, revision uint64) (contract.Resource, error) {
	m.mu.Lock()
	r, err := m.options.Store.Save(ctx, c, revision)
	if err == nil && m.activeID == c.ID && m.activeCancel != nil {
		m.activeCancel()
	}
	m.mu.Unlock()
	if err != nil {
		return r, err
	}
	if err := m.Cache.Reload(ctx, m.options.Now()); err != nil {
		m.report("certificate_cache_unavailable")
	}
	m.Wake()
	return r, nil
}

func (m *Manager) Delete(ctx context.Context, id string, revision uint64) error {
	m.mu.Lock()
	err := m.options.Store.Delete(ctx, id, revision)
	if err == nil && m.activeID == id && m.activeCancel != nil {
		m.activeCancel()
	}
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if err := m.Cache.Reload(ctx, m.options.Now()); err != nil {
		m.report("certificate_cache_unavailable")
	}
	m.Wake()
	return nil
}

func (m *Manager) Renew(ctx context.Context, id string, revision uint64) (contract.Resource, error) {
	r, err := m.options.Store.Queue(ctx, id, revision, m.options.Now())
	if err == nil {
		m.Wake()
	}
	return r, err
}

func (m *Manager) List(ctx context.Context) ([]contract.Resource, error) {
	resources, err := m.options.Store.List(ctx)
	if err == nil {
		m.publishMetrics(resources)
	}
	for i := range resources {
		r := &resources[i]
		if !r.Status.NotAfter.IsZero() && !m.options.Now().Before(r.Status.NotAfter) {
			r.Status.State = "expired"
		}
	}
	return resources, err
}

func (m *Manager) loop(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		next, err := m.step(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.report("certificate_worker_failed")
			next = m.options.Now().Add(time.Minute)
		}
		var deadline <-chan time.Time
		if !next.IsZero() {
			timer.Reset(max(time.Millisecond, next.Sub(m.options.Now())))
			deadline = timer.C
		} else {
			timer.Stop()
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-deadline:
		}
	}
}

func earlier(a, b time.Time) time.Time {
	if b.IsZero() || !a.IsZero() && a.Before(b) {
		return a
	}
	return b
}

// step is serial; tests advance an injected clock instead of contacting an
// external CA or sleeping through certificate lifetimes.
func (m *Manager) step(ctx context.Context) (time.Time, error) {
	resources, err := m.options.Store.List(ctx)
	if err != nil {
		return time.Time{}, err
	}
	m.publishMetrics(resources)
	now := m.options.Now()
	var next time.Time
	cleanupAt, err := m.options.Store.NextDNSCleanup(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if m.cleanupRetry.After(cleanupAt) && !cleanupAt.IsZero() {
		cleanupAt = m.cleanupRetry
	}
	if !cleanupAt.IsZero() && !cleanupAt.After(now) && m.options.Cleanup != nil {
		bounded, cancel := context.WithTimeout(ctx, time.Minute)
		err := m.options.Cleanup(bounded)
		cancel()
		if err != nil {
			m.report("dns_cleanup_pending")
			m.cleanupRetry = now.Add(5 * time.Minute)
			cleanupAt = m.cleanupRetry
		} else {
			cleanupAt, err = m.options.Store.NextDNSCleanup(ctx)
			if err != nil {
				return time.Time{}, err
			}
		}
	}
	if m.options.Cleanup != nil {
		next = earlier(next, cleanupAt)
	}
	var selected *contract.Resource
	var selectedDue time.Time
	for _, r := range resources {
		due := nextDue(r)
		if due.IsZero() {
			continue
		}
		if due.After(now) {
			next = earlier(next, due)
			continue
		}
		if selected == nil || due.Before(selectedDue) {
			selected = new(r)
			selectedDue = due
		}
	}
	if selected != nil {
		attempted, err := m.issue(ctx, *selected)
		if err != nil {
			return time.Time{}, err
		}
		if attempted {
			return m.options.Now(), nil
		}
		next = earlier(next, now.Add(time.Minute))
	}
	return next, nil
}

func (m *Manager) issue(ctx context.Context, r contract.Resource) (bool, error) {
	now := m.options.Now()
	owner := uuid.New().String()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false, nil
	}
	ok, err := m.options.Store.Acquire(ctx, r.Config.ID, r.Revision, owner, now, 9*time.Minute)
	if err != nil || !ok {
		m.mu.Unlock()
		return false, err
	}
	bounded, cancel := context.WithTimeout(ctx, 8*time.Minute)
	m.activeID = r.Config.ID
	m.activeCancel = cancel
	m.mu.Unlock()
	defer func() { cancel(); m.mu.Lock(); m.activeID = ""; m.activeCancel = nil; m.mu.Unlock() }()
	material, issueErr := m.options.Issue(bounded, r.Config)
	status := r.Status
	var publish *certificates.Material
	if issueErr == nil {
		pair, err := ValidateMaterial(r.Config, material, m.options.Now())
		if err != nil {
			issueErr = err
		} else {
			var window RenewalWindow
			if m.options.RenewalInfo != nil {
				if w, err := m.options.RenewalInfo(bounded, r.Config, pair); err == nil {
					window = w
				} else {
					m.report("certificate_renewal_info_unavailable")
				}
			}
			leaf := pair.Leaf
			status = contract.Status{State: "ready", Issuer: leaf.Issuer.String(), Serial: leaf.SerialNumber.String(), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, LastAttempt: now, LastSuccess: m.options.Now(), NextAttempt: renewalTime(r.Config.ID, leaf.SerialNumber.String(), leaf.NotBefore, leaf.NotAfter, window)}
			publish = &material
		}
	}
	if issueErr != nil {
		status = failureStatus(r, m.options.Now(), issueErr)
	}
	// Preserve a resumable lease on shutdown. An ordinary user/config cancel is
	// revision-fenced; it cannot publish a stale pair or overwrite newer status.
	if ctx.Err() != nil {
		return true, nil
	}
	if err := m.options.Store.Complete(ctx, r.Config.ID, r.Revision, owner, m.options.Now(), status, publish); err != nil {
		if errors.Is(err, certificates.ErrConflict) {
			return true, nil
		}
		return true, err
	}
	if issueErr != nil {
		m.failures.Add(1)
		m.report(status.FailureCode)
	} else {
		m.successes.Add(1)
		m.report("certificate_issued")
	}
	if err := m.Cache.Reload(ctx, m.options.Now()); err != nil {
		m.report("certificate_cache_unavailable")
	}
	return true, nil
}
