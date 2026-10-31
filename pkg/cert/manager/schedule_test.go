package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
	"golang.org/x/crypto/acme"
)

func signedMaterial(t *testing.T, ca *testCA, cfg contract.Config, now time.Time, serial int64) certificates.Material {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: cfg.Domains, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.root, &key.PublicKey, ca.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := encodeSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return certificates.Material{CertificatePEM: encodeChain([][]byte{der, ca.root.Raw}), PrivateKey: private}
}

func managerStore(t *testing.T) *certificates.Store {
	t.Helper()
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return certificates.New(db.DB())
}

func TestRenewalJitterWindowAndBackoff(t *testing.T) {
	now := time.Now()
	end := now.Add(90 * 24 * time.Hour)
	first := renewalTime("a", "1", now, end, RenewalWindow{})
	if first.Before(now.Add(54*24*time.Hour)) || !first.Before(now.Add(68*24*time.Hour)) || renewalTime("a", "1", now, end, RenewalWindow{}) != first {
		t.Fatal("unstable lifetime schedule", first)
	}
	if renewalTime("b", "1", now, end, RenewalWindow{}).Equal(first) {
		t.Fatal("missing renewal jitter")
	}
	window := RenewalWindow{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)}
	chosen := renewalTime("a", "1", now, end, window)
	if chosen.Before(window.Start) || !chosen.Before(window.End) {
		t.Fatal("CA renewal window ignored")
	}
	if renewalTime("a", "1", now, end, RenewalWindow{Start: end, End: now}) != first {
		t.Fatal("invalid CA window displaced fallback")
	}
	r := contract.Resource{Config: contract.Config{ID: uuid.New().String()}}
	previous := time.Duration(0)
	for range 16 {
		r.Status = failureStatus(r, now, errors.New("sensitive raw CA detail"))
		delay := r.Status.NextAttempt.Sub(now)
		if r.Status.Failures <= 10 && delay < previous || delay > 8*time.Hour || r.Status.FailureCode != "acme_request_failed" {
			t.Fatal(delay, r.Status)
		}
		previous = delay
	}
	rate := failureStatus(r, now, &acme.Error{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"86400"}}})
	if rate.FailureCode != "ca_rate_limited" || rate.NextAttempt.Before(now.Add(24*time.Hour)) {
		t.Fatal("CA Retry-After bypassed", rate)
	}
}

func TestManagerPersistentRenewalFailureAndManualLimits(t *testing.T) {
	ca := newTestCA(t)
	store := managerStore(t)
	cfg := ca.config()
	now := time.Now()
	calls := 0
	fail := false
	issue := func(context.Context, contract.Config) (certificates.Material, error) {
		calls++
		if fail {
			return certificates.Material{}, &acme.Error{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"3600"}}}
		}
		return signedMaterial(t, ca, cfg, now, int64(calls+1)), nil
	}
	m, err := New(Options{Store: store, Issue: issue, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.Save(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err = store.Get(t.Context(), cfg.ID)
	if err != nil || r.Status.State != "ready" || calls != 1 {
		t.Fatal(r.Status, calls, err)
	}
	point := r.Status.NextAttempt
	// A fresh worker restores the deadline without an immediate reissuance.
	restarted, err := New(m.options)
	if err != nil {
		t.Fatal(err)
	}
	if due, err := restarted.step(t.Context()); err != nil || !due.Equal(point) || calls != 1 {
		t.Fatal("restart lost schedule", due, calls, err)
	}
	now = point.Add(time.Second)
	fail = true
	if _, err := restarted.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	failed, err := store.Get(t.Context(), cfg.ID)
	if err != nil || failed.Status.FailureCode != "ca_rate_limited" || failed.Status.NotAfter != r.Status.NotAfter || calls != 2 {
		t.Fatal(failed.Status, calls, err)
	}
	retained, err := store.Material(t.Context(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ValidateMaterial(cfg, retained, now)
	if err != nil || pair.Leaf.SerialNumber.String() != r.Status.Serial {
		t.Fatal("failed renewal replaced old material", err)
	}
	queued, err := restarted.Renew(t.Context(), cfg.ID, r.Revision)
	if err != nil || !queued.Status.NextAttempt.Equal(failed.Status.NextAttempt) {
		t.Fatal("manual action bypassed rate limit", queued.Status, err)
	}
	if _, err := restarted.step(t.Context()); err != nil || calls != 2 {
		t.Fatal("request replayed before backoff", calls, err)
	}
	now = failed.Status.NextAttempt.Add(time.Second)
	fail = false
	if _, err := restarted.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err = store.Get(t.Context(), cfg.ID)
	if err != nil || r.Status.State != "ready" || r.Status.Failures != 0 || calls != 3 {
		t.Fatal(r.Status, calls, err)
	}
	cfg.AutoRenew = false
	r, err = restarted.Save(t.Context(), cfg, r.Revision)
	if err != nil {
		t.Fatal(err)
	}
	now = r.Status.NextAttempt.Add(time.Hour)
	if _, err := restarted.step(t.Context()); err != nil || calls != 3 {
		t.Fatal("automatic renewal ran while disabled", calls, err)
	}
}

func TestManagerLeaseDeduplicationAndCancellation(t *testing.T) {
	ca := newTestCA(t)
	store := managerStore(t)
	cfg := ca.config()
	entered := make(chan struct{})
	canceled := make(chan struct{})
	var once sync.Once
	var active, maxActive atomic.Int32
	issuer := func(ctx context.Context, c contract.Config) (certificates.Material, error) {
		count := active.Add(1)
		for current := maxActive.Load(); count > current && !maxActive.CompareAndSwap(current, count); current = maxActive.Load() {
		}
		defer active.Add(-1)
		once.Do(func() { close(entered) })
		<-ctx.Done()
		close(canceled)
		return certificates.Material{}, ctx.Err()
	}
	m, err := New(Options{Store: store, Issue: issuer})
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.Save(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
	otherCalls := 0
	other, err := New(Options{Store: store, Issue: func(context.Context, contract.Config) (certificates.Material, error) {
		otherCalls++
		return certificates.Material{}, errors.New("duplicate")
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.step(t.Context()); err != nil || otherCalls != 0 {
		t.Fatal("second instance duplicated issuance", otherCalls, err)
	}
	if _, err := m.Renew(t.Context(), cfg.ID, r.Revision); !errors.Is(err, certificates.ErrConflict) {
		t.Fatal("manual action overlapped active issuance", err)
	}
	cfg.Name = "Changed while issuing"
	r, err = m.Save(t.Context(), cfg, r.Revision)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("configuration did not cancel old request")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	final, err := store.Get(t.Context(), cfg.ID)
	if err != nil || final.Revision != r.Revision || final.Status.State != "queued" || active.Load() != 0 || maxActive.Load() != 1 {
		t.Fatal("stale completion or worker leak", final.Status, active.Load(), maxActive.Load(), err)
	}
}

func TestManagerInterruptedLeaseRecoveryAndFairAdmission(t *testing.T) {
	ca := newTestCA(t)
	t.Run("interrupted_manual_job", func(t *testing.T) {
		store := managerStore(t)
		cfg := ca.config()
		cfg.AutoRenew = false
		r, err := store.Save(t.Context(), cfg, 0)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		owner := uuid.New().String()
		if ok, err := store.Acquire(t.Context(), cfg.ID, r.Revision, owner, now, 9*time.Minute); err != nil || !ok {
			t.Fatal(ok, err)
		}
		calls := 0
		m, err := New(Options{Store: store, Now: func() time.Time { return now }, Issue: func(context.Context, contract.Config) (certificates.Material, error) {
			calls++
			return signedMaterial(t, ca, cfg, now, 2), nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.step(t.Context()); err != nil || calls != 0 {
			t.Fatal("restarted worker ignored active lease", calls, err)
		}
		now = now.Add(10 * time.Minute)
		if _, err := m.step(t.Context()); err != nil || calls != 1 {
			t.Fatal("interrupted job was not recovered", calls, err)
		}
	})
	t.Run("overdue_jobs_and_cleanup", func(t *testing.T) {
		store := managerStore(t)
		cfg := ca.config()
		cfg.ID = "00000000-0000-4000-8000-000000000001"
		r, err := store.Save(t.Context(), cfg, 0)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		old := now.Add(-time.Hour)
		owner := uuid.New().String()
		if ok, err := store.Acquire(t.Context(), cfg.ID, r.Revision, owner, old, time.Minute); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if err := store.Complete(t.Context(), cfg.ID, r.Revision, owner, old, contract.Status{State: "failed", Failures: 1, NextAttempt: now.Add(-time.Minute)}, nil); err != nil {
			t.Fatal(err)
		}
		fresh := cfg
		fresh.ID = "00000000-0000-4000-8000-000000000002"
		if _, err := store.Save(t.Context(), fresh, 0); err != nil {
			t.Fatal(err)
		}
		p, err := store.SaveProvider(t.Context(), contract.DNSProvider{ID: uuid.New().String(), Name: "zone", Type: "cloudflare", ZoneID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ZoneName: "example.com"}, certificates.NewSecret([]byte("token")))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.AddDNSCleanup(t.Context(), certificates.DNSCleanup{ID: uuid.New().String(), ProviderID: p.ID, Name: "_acme-challenge.example.com", Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NotBefore: now.Add(-time.Second).UnixMilli()}, old); err != nil {
			t.Fatal(err)
		}
		var admitted []string
		cleanups := 0
		m, err := New(Options{Store: store, Now: func() time.Time { return now }, Cleanup: func(context.Context) error { cleanups++; return errors.New("retry cleanup") }, Issue: func(ctx context.Context, c contract.Config) (certificates.Material, error) {
			admitted = append(admitted, c.ID)
			return certificates.Material{}, errors.New("retry CA")
		}})
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := m.step(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		if len(admitted) != 2 || admitted[0] != fresh.ID || admitted[1] != cfg.ID || cleanups != 1 {
			t.Fatal("starvation or repeated cleanup before backoff", admitted, cleanups)
		}
	})
}
