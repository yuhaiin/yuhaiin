package gateway

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync/atomic"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"golang.org/x/time/rate"
)

type backend struct {
	url              *url.URL
	weight           uint64
	active           atomic.Int64
	failures         atomic.Int64
	unavailableUntil atomic.Int64
}

type upstream struct {
	config   contract.Upstream
	backends []*backend
	next     atomic.Uint64
	limiter  *rate.Limiter
	active   atomic.Int64
}

func compileUpstream(config contract.Upstream) (*upstream, error) {
	if config.ID == "" || len(config.Backends) == 0 || len(config.Backends) > 256 {
		return nil, errors.New("upstream requires an ID and 1..256 backends")
	}
	if !slices.Contains([]string{"", "round_robin", "weighted_round_robin", "least_requests"}, config.Balance) {
		return nil, errors.New("unsupported balance policy")
	}
	if config.ConnectTimeoutMS < 0 || config.IdleTimeoutMS < 0 || config.RequestTimeoutMS < 0 || config.StreamIdleMS < 0 || config.MaxConnections < 0 || config.MaxConcurrent < 0 || config.RequestsPerSecond < 0 || config.Burst < 0 || config.HealthIntervalMS < 0 || config.FailureThreshold < 0 || config.RecoveryMS < 0 || config.Retries < 0 || config.Retries > 3 {
		return nil, errors.New("invalid upstream limit")
	}
	if config.HealthPath != "" && config.HealthPath[0] != '/' {
		return nil, errors.New("health path must start with /")
	}
	if err := validateAction(contract.Action{Type: "forward", Outbound: config.Outbound}); err != nil {
		return nil, err
	}
	u := &upstream{config: config}
	if config.TrustPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(config.TrustPEM)) {
		return nil, errors.New("upstream trust contains no certificates")
	}
	if config.RequestsPerSecond > 0 {
		u.limiter = rate.NewLimiter(rate.Limit(config.RequestsPerSecond), max(config.Burst, 1))
	}
	for _, b := range config.Backends {
		parsed, err := url.Parse(b.URL)
		if err != nil || parsed == nil || !slices.Contains([]string{"http", "https"}, parsed.Scheme) || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("invalid HTTP backend %q", b.URL)
		}
		if b.Weight < 0 || b.Weight > 10000 {
			return nil, errors.New("backend weight must be 0..10000")
		}
		u.backends = append(u.backends, &backend{url: parsed, weight: uint64(max(b.Weight, 1))})
	}
	return u, nil
}

func (u *upstream) acquire() (func(), error) {
	if u.limiter != nil && !u.limiter.Allow() {
		return nil, errors.New("upstream rate limit exceeded")
	}
	n := u.active.Add(1)
	if u.config.MaxConcurrent > 0 && n > int64(u.config.MaxConcurrent) {
		u.active.Add(-1)
		return nil, errors.New("upstream concurrency limit exceeded")
	}
	return func() { u.active.Add(-1) }, nil
}

func (u *upstream) pick() (*backend, error) {
	now := time.Now().UnixNano()
	var total uint64
	var least *backend
	for _, b := range u.backends {
		if b.unavailableUntil.Load() > now {
			continue
		}
		if least == nil || b.active.Load() < least.active.Load() {
			least = b
		}
		if u.config.Balance == "weighted_round_robin" {
			total += b.weight
		} else {
			total++
		}
	}
	if total == 0 {
		return nil, errors.New("no healthy upstream backends")
	}
	if u.config.Balance == "least_requests" {
		least.active.Add(1)
		return least, nil
	}
	n := (u.next.Add(1) - 1) % total
	for _, b := range u.backends {
		if b.unavailableUntil.Load() > now {
			continue
		}
		weight := uint64(1)
		if u.config.Balance == "weighted_round_robin" {
			weight = b.weight
		}
		if n < weight {
			b.active.Add(1)
			return b, nil
		}
		n -= weight
	}
	return nil, errors.New("upstream health changed during selection")
}

func (u *upstream) finish(b *backend, failed bool) {
	b.active.Add(-1)
	u.recordHealth(b, failed)
}

func (u *upstream) recordHealth(b *backend, failed bool) {
	if !failed {
		b.failures.Store(0)
		b.unavailableUntil.Store(0)
		return
	}
	if b.failures.Add(1) >= int64(max(u.config.FailureThreshold, 3)) {
		b.unavailableUntil.Store(time.Now().Add(durationMS(u.config.RecoveryMS, 30*time.Second)).UnixNano())
	}
}
