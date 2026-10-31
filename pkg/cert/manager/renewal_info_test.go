package manager

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
	"golang.org/x/crypto/acme"
)

type ariAdvice struct {
	window  RenewalWindow
	retry   string
	failure bool
}
type ariPeer struct {
	server *httptest.Server
	advice atomic.Pointer[ariAdvice]
	calls  atomic.Int32
	mu     sync.Mutex
	ids    []string
}

func localARIPeer(t *testing.T, now time.Time) *ariPeer {
	t.Helper()
	peer := new(ariPeer)
	peer.advice.Store(&ariAdvice{window: RenewalWindow{now.Add(10 * time.Hour), now.Add(12 * time.Hour)}, retry: "21600"})
	peer.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer.calls.Add(1)
		if r.URL.Path == "/directory" {
			_ = json.MarshalWrite(w, map[string]string{"renewalInfo": "https://" + r.Host + "/ari"})
			return
		}
		peer.mu.Lock()
		peer.ids = append(peer.ids, strings.TrimPrefix(r.URL.Path, "/ari/"))
		peer.mu.Unlock()
		advice := peer.advice.Load()
		w.Header().Set("Retry-After", advice.retry)
		if advice.failure {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.MarshalWrite(w, map[string]any{"suggestedWindow": map[string]time.Time{"start": advice.window.Start, "end": advice.window.End}})
	}))
	t.Cleanup(peer.server.Close)
	return peer
}
func (p *ariPeer) identifiers() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.ids)
}

type ariClock struct{ nanoseconds atomic.Int64 }

func (c *ariClock) now() time.Time      { return time.Unix(0, c.nanoseconds.Load()).UTC() }
func (c *ariClock) set(value time.Time) { c.nanoseconds.Store(value.UnixNano()) }

func TestARIPersistentRefreshUrgencyAndReplacement(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := new(ariClock)
	clock.set(now)
	ca := newTestCA(t)
	peer := localARIPeer(t, now)
	cfg := ca.config()
	cfg.DirectoryURL = peer.server.URL + "/directory"
	store := managerStore(t)
	issuances := 0
	options := Options{Store: store, Now: clock.now, Issue: func(context.Context, contract.Config) (certificates.Material, error) {
		issuances++
		return signedMaterial(t, ca, cfg, clock.now(), int64(issuances+1)), nil
	}, RenewalInfo: func(ctx context.Context, c contract.Config, pair *tls.Certificate) (RenewalInformation, error) {
		return FetchRenewalInfo(ctx, peer.server.Client(), c, pair, clock.now())
	}}
	m, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err = m.Save(t.Context(), cfg, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = m.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err := store.Get(t.Context(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	info := r.Status.RenewalInfo
	if info == nil || info.State != "available" || !info.NextCheck.Equal(now.Add(6*time.Hour)) || r.Status.NextAttempt.Before(info.WindowStart) || !r.Status.NextAttempt.Before(info.WindowEnd) {
		t.Fatal("initial CA advice not persisted", r.Status)
	}
	before := peer.calls.Load()
	if next, err := m.step(t.Context()); err != nil || !next.Equal(info.NextCheck) || peer.calls.Load() != before {
		t.Fatal("idle worker queried CA or changed schedule", next, err)
	}
	// A new manager restores the same private store/cache and persisted deadline.
	restarted, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.Cache.Reload(t.Context(), clock.now()); err != nil {
		t.Fatal(err)
	}
	if next, err := restarted.step(t.Context()); err != nil || !next.Equal(info.NextCheck) || peer.calls.Load() != before {
		t.Fatal("restart changed ARI plan", next, err)
	}
	clock.set(info.NextCheck)
	peer.advice.Store(&ariAdvice{window: RenewalWindow{clock.now().Add(-2 * time.Hour), clock.now().Add(-time.Hour)}, retry: "21600"})
	if _, err := restarted.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err = store.Get(t.Context(), cfg.ID)
	if err != nil || r.Status.NextAttempt.After(clock.now()) || issuances != 1 {
		t.Fatal("past CA window did not queue urgent renewal", r.Status, issuances, err)
	}
	if _, err := restarted.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err = store.Get(t.Context(), cfg.ID)
	if err != nil || issuances != 2 || !r.Status.NextAttempt.Equal(clock.now().Add(certificates.ManualAttemptInterval)) {
		t.Fatal("urgent advice caused an unbounded issuance loop", r.Status, issuances, err)
	}
	calls := peer.calls.Load()
	if _, err := restarted.step(t.Context()); err != nil || peer.calls.Load() != calls || issuances != 2 {
		t.Fatal("minimum issuance interval bypassed", err)
	}
	ids := peer.identifiers()
	if len(ids) != 3 || ids[0] != ids[1] || ids[2] == ids[0] {
		t.Fatal("replaced certificate was refreshed", ids)
	}
}

func TestARIFailureKeepsCertificateScheduleAndIssuanceBackoff(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := new(ariClock)
	clock.set(now)
	ca := newTestCA(t)
	peer := localARIPeer(t, now)
	cfg := ca.config()
	cfg.DirectoryURL = peer.server.URL + "/directory"
	store := managerStore(t)
	failIssuance := false
	m, err := New(Options{Store: store, Now: clock.now, Issue: func(context.Context, contract.Config) (certificates.Material, error) {
		if failIssuance {
			return certificates.Material{}, &acme.Error{StatusCode: 429, Header: http.Header{"Retry-After": []string{"3600"}}}
		}
		return signedMaterial(t, ca, cfg, clock.now(), 2), nil
	}, RenewalInfo: func(ctx context.Context, c contract.Config, pair *tls.Certificate) (RenewalInformation, error) {
		return FetchRenewalInfo(ctx, peer.server.Client(), c, pair, clock.now())
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.Save(t.Context(), cfg, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	original, err := store.Get(t.Context(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	old := m.Cache.snapshot.Load().pairs[cfg.ID]
	peer.advice.Store(&ariAdvice{retry: "300", failure: true})
	r := original
	for attempt := range 6 {
		clock.set(r.Status.RenewalInfo.NextCheck)
		if _, err := m.step(t.Context()); err != nil {
			t.Fatal(err)
		}
		r, err = store.Get(t.Context(), cfg.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status.State != "ready" || r.Status.Failures != 0 || !r.Status.NextAttempt.Equal(original.Status.NextAttempt) || !r.Status.LastAttempt.Equal(original.Status.LastAttempt) || r.Status.RenewalInfo.State != "unavailable" || r.Status.RenewalInfo.Failures != attempt+1 {
			t.Fatal("ARI failure displaced healthy certificate/issuance state", r.Status)
		}
		delay := r.Status.RenewalInfo.NextCheck.Sub(clock.now())
		if delay < 5*time.Minute || attempt == 5 && delay != 6*time.Hour {
			t.Fatal("unbounded retry or Retry-After ignored", delay)
		}
	}
	if !bytes.Equal(m.Cache.snapshot.Load().pairs[cfg.ID].Certificate[0], old.Certificate[0]) || m.failures.Load() != 0 {
		t.Fatal("metadata failure replaced or failed the certificate")
	}
	// The next real issuance fails; metadata is never refreshed during its backoff.
	failIssuance = true
	clock.set(r.Status.NextAttempt)
	if _, err := m.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	failed, err := store.Get(t.Context(), cfg.ID)
	if err != nil || failed.Status.State != "failed" || failed.Status.Failures != 1 {
		t.Fatal(failed.Status, err)
	}
	before := peer.calls.Load()
	if _, err := m.step(t.Context()); err != nil || peer.calls.Load() != before {
		t.Fatal("metadata bypassed failed issuance backoff", err)
	}
	queued, err := m.Renew(t.Context(), cfg.ID, failed.Revision)
	if err != nil || !queued.Status.NextAttempt.Equal(failed.Status.NextAttempt) || queued.Status.Failures != failed.Status.Failures {
		t.Fatal("manual renewal reset issuance backoff", queued.Status, err)
	}
	if !bytes.Equal(m.Cache.snapshot.Load().pairs[cfg.ID].Certificate[0], old.Certificate[0]) {
		t.Fatal("failed renewal discarded old material")
	}
}

func TestARIRefreshDedupConfigurationCancellationAndDeletion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := new(ariClock)
	clock.set(now)
	ca := newTestCA(t)
	peer := localARIPeer(t, now)
	cfg := ca.config()
	cfg.DirectoryURL = peer.server.URL + "/directory"
	store := managerStore(t)
	var blocking atomic.Bool
	var calls atomic.Int32
	var entered chan struct{}
	options := Options{Store: store, Now: clock.now, Issue: func(context.Context, contract.Config) (certificates.Material, error) {
		return signedMaterial(t, ca, cfg, clock.now(), 2), nil
	}, RenewalInfo: func(ctx context.Context, c contract.Config, pair *tls.Certificate) (RenewalInformation, error) {
		if blocking.Load() {
			calls.Add(1)
			close(entered)
			<-ctx.Done()
			return RenewalInformation{}, ctx.Err()
		}
		return FetchRenewalInfo(ctx, peer.server.Client(), c, pair, clock.now())
	}}
	m, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err = m.Save(t.Context(), cfg, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = m.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err := store.Get(t.Context(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	clock.set(r.Status.RenewalInfo.NextCheck)
	blocking.Store(true)
	entered = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, err := m.step(t.Context()); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not begin")
	}
	other, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.Cache.Reload(t.Context(), clock.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := other.step(t.Context()); err != nil || calls.Load() != 1 {
		t.Fatal("duplicate refresh", calls.Load(), err)
	}
	cfg.Name = "Changed during refresh"
	updated, err := m.Save(t.Context(), cfg, r.Revision)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("configuration did not cancel old refresh")
	}
	r, err = store.Get(t.Context(), cfg.ID)
	if err != nil || r.Revision != updated.Revision || r.Status.RenewalInfo.State != "available" {
		t.Fatal("stale cancellation overwrote new revision", r, err)
	}
	clock.set(r.Status.RenewalInfo.NextCheck)
	entered = make(chan struct{})
	go func() { _, err := m.step(t.Context()); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("second refresh did not begin")
	}
	if err := m.Delete(t.Context(), cfg.ID, r.Revision); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("delete did not cancel refresh")
	}
	resources, err := store.List(t.Context())
	if err != nil || len(resources) != 0 {
		t.Fatal("refresh resurrected a deleted resource", resources, err)
	}
}

func TestARIRestartRecoversInterruptedRefreshLease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := new(ariClock)
	clock.set(now)
	ca := newTestCA(t)
	peer := localARIPeer(t, now)
	cfg := ca.config()
	cfg.DirectoryURL = peer.server.URL + "/directory"
	store := managerStore(t)
	var blocking atomic.Bool
	entered := make(chan struct{})
	options := Options{Store: store, Now: clock.now, Issue: func(context.Context, contract.Config) (certificates.Material, error) {
		return signedMaterial(t, ca, cfg, clock.now(), 2), nil
	}, RenewalInfo: func(ctx context.Context, c contract.Config, pair *tls.Certificate) (RenewalInformation, error) {
		if blocking.Load() {
			close(entered)
			<-ctx.Done()
			return RenewalInformation{}, ctx.Err()
		}
		return FetchRenewalInfo(ctx, peer.server.Client(), c, pair, clock.now())
	}}
	m, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.Save(t.Context(), cfg, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err := store.Get(t.Context(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	clock.set(r.Status.RenewalInfo.NextCheck)
	blocking.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := m.step(ctx); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel refresh")
	}
	blocking.Store(false)
	restarted, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.Cache.Reload(t.Context(), clock.now()); err != nil {
		t.Fatal(err)
	}
	before := peer.calls.Load()
	if next, err := restarted.step(t.Context()); err != nil || peer.calls.Load() != before || !next.Equal(clock.now().Add(2*time.Minute)) {
		t.Fatal("restart bypassed retained lease", next, err)
	}
	clock.set(clock.now().Add(2 * time.Minute))
	if _, err := restarted.step(t.Context()); err != nil || peer.calls.Load() != before+2 {
		t.Fatal("expired refresh lease did not recover", err)
	}
}

func TestARIDisabledAndExpiredCertificatesDoNotRefresh(t *testing.T) {
	now := time.Now()
	for _, r := range []contract.Resource{
		{Config: contract.Config{AutoRenew: false}, Status: contract.Status{State: "ready", Serial: "1", NotAfter: now.Add(time.Hour)}},
		{Config: contract.Config{AutoRenew: true}, Status: contract.Status{State: "ready", Serial: "1", NotAfter: now}},
		{Config: contract.Config{AutoRenew: true}, Status: contract.Status{State: "failed", Serial: "1", NotAfter: now.Add(time.Hour), Failures: 1}},
	} {
		if !renewalInfoDue(r, now).IsZero() {
			t.Fatal("ineligible certificate scheduled ARI", r.Status)
		}
	}
}

func TestARIPersistedFailureCounterCannotOverflowOrPanic(t *testing.T) {
	now := time.Now()
	ca := newTestCA(t)
	cfg := ca.config()
	pair, err := ValidateMaterial(cfg, signedMaterial(t, ca, cfg, now, 2), now)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{Store: managerStore(t), Now: func() time.Time { return now }, Issue: func(context.Context, contract.Config) (certificates.Material, error) {
		return certificates.Material{}, nil
	}, RenewalInfo: func(context.Context, contract.Config, *tls.Certificate) (RenewalInformation, error) {
		return RenewalInformation{}, &renewalInfoError{temporary: true}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, count := range []int{-1, math.MinInt, math.MaxInt} {
		status := contract.Status{State: "failed", Failures: 2, NextAttempt: now.Add(time.Hour), RenewalInfo: &contract.RenewalInfoStatus{Failures: count}}
		result := m.applyRenewalInfo(t.Context(), cfg, pair, status)
		if result.RenewalInfo.Failures < 1 || result.RenewalInfo.Failures > 1000 || !result.RenewalInfo.NextCheck.After(now) || !result.NextAttempt.Equal(status.NextAttempt) || result.Failures != 2 {
			t.Fatal("invalid persisted counter changed backoff", result)
		}
	}
}
