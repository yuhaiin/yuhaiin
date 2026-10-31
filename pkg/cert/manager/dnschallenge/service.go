// Package dnschallenge coordinates durable, owned DNS-01 records. Provider
// adapters implement the wire API; this owner handles receipts and DNS evidence.
package dnschallenge

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

type Error struct {
	Code       string
	RetryAfter time.Duration
}

func (e *Error) Error() string { return e.Code }

// Provider must create a unique tagged TXT record and clean up only records
// whose name, content and ownership tag still match this receipt.
type Provider interface {
	Create(context.Context, contract.DNSProvider, certificates.Secret, certificates.DNSCleanup) (string, error)
	Cleanup(context.Context, contract.DNSProvider, certificates.Secret, certificates.DNSCleanup) error
}

type Options struct {
	// LookupTXT uses the application's existing governed resolver. There is no
	// fallback to a system or hardcoded public resolver.
	LookupTXT func(context.Context, string) ([]string, error)
	Now       func() time.Time
	Wait      func(context.Context, time.Duration) error
}

type Service struct {
	store     *certificates.Store
	providers map[string]Provider
	options   Options
}

func New(store *certificates.Store, providers map[string]Provider, options Options) (*Service, error) {
	if store == nil || len(providers) == 0 || options.LookupTXT == nil {
		return nil, errors.New("DNS-01 requires storage, providers and governed DNS")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Wait == nil {
		options.Wait = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	return &Service{store: store, providers: maps.Clone(providers), options: options}, nil
}

func (s *Service) Present(ctx context.Context, providerID, domain, value string) (func(), error) {
	domain = strings.TrimPrefix(domain, "*.")
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	deadline, bounded := ctx.Deadline()
	if !contract.ValidDomain(domain, false) || len(domain)+len("_acme-challenge.") > 253 || err != nil || len(decoded) != 32 || !bounded || deadline.Sub(s.options.Now()) > 10*time.Minute {
		return nil, &Error{Code: "dns_invalid_challenge"}
	}
	p, token, err := s.store.Provider(ctx, providerID)
	if err != nil || token.Empty() {
		return nil, &Error{Code: "dns_provider_unavailable"}
	}
	provider := s.providers[p.Type]
	if provider == nil || !certificates.ValidProvider(p) || domain != p.ZoneName && !strings.HasSuffix(domain, "."+p.ZoneName) {
		return nil, &Error{Code: "dns_zone_mismatch"}
	}
	now := s.options.Now()
	receipt := certificates.DNSCleanup{ID: uuid.New().String(), ProviderID: providerID, Name: "_acme-challenge." + domain, Value: value, NotBefore: deadline.Add(2 * time.Minute).UnixMilli()}
	if err := s.store.AddDNSCleanup(ctx, receipt, now); err != nil {
		return nil, err
	}
	cleanup := sync.OnceFunc(func() {
		// Cleanup must survive a canceled authorization but stays bounded and
		// synchronous in the shared worker. Failure leaves a durable receipt.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = s.cleanup(cleanupCtx, receipt)
	})
	id, err := provider.Create(ctx, p, token, receipt)
	if err != nil {
		cleanup()
		return nil, err
	}
	receipt.RecordID = id
	if err = s.store.UpdateDNSCleanup(ctx, receipt); err != nil {
		cleanup()
		return nil, err
	}
	propagationCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		values, err := s.options.LookupTXT(propagationCtx, receipt.Name)
		if err == nil && slices.Contains(values, value) {
			return cleanup, nil
		}
		if err := s.options.Wait(propagationCtx, 5*time.Second); err != nil {
			cleanup()
			return nil, &Error{Code: "dns_propagation_timeout"}
		}
	}
}

func (s *Service) cleanup(ctx context.Context, r certificates.DNSCleanup) error {
	// If POST's reply was lost, wait until the bounded operation and settling
	// interval ended before reconciling an empty list as successful cleanup.
	if r.RecordID == "" && s.options.Now().UnixMilli() < r.NotBefore {
		return &Error{Code: "dns_create_outcome_pending"}
	}
	p, token, err := s.store.Provider(ctx, r.ProviderID)
	if err != nil {
		return &Error{Code: "dns_provider_unavailable"}
	}
	provider := s.providers[p.Type]
	if provider == nil {
		return &Error{Code: "dns_provider_unavailable"}
	}
	if err := provider.Cleanup(ctx, p, token, r); err != nil {
		return err
	}
	return s.store.FinishDNSCleanup(ctx, r.ID)
}

// Reconcile runs in the shared certificate worker at startup and on a bounded
// retry schedule. No record cleanup creates a permanent background goroutine.
func (s *Service) Reconcile(ctx context.Context) error {
	receipts, err := s.store.PendingDNSCleanup(ctx, s.options.Now())
	if err != nil {
		return err
	}
	var failures []error
	for _, r := range receipts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.cleanup(ctx, r); err != nil {
			failures = append(failures, err)
			delay := 5 * time.Minute
			if problem, ok := errors.AsType[*Error](err); ok {
				delay = max(delay, min(7*24*time.Hour, problem.RetryAfter))
			}
			r.NotBefore = s.options.Now().Add(delay).UnixMilli()
			if err := s.store.UpdateDNSCleanup(ctx, r); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}
