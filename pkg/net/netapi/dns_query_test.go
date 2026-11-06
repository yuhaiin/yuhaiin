package netapi

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
)

type opaqueDNS struct {
	Resolver
	calls int
}

func (r *opaqueDNS) Raw(ctx context.Context, q DNSQuestion) (*dns.Msg, error) {
	r.calls++
	// The outer query holds the only permit. Nested DNS must not acquire it again.
	nested, permit, err := AcquireDNSQuery(ctx)
	if err != nil || permit != nil || nested != ctx {
		return nil, errors.New("nested DNS retained admission limiter")
	}
	return NewDNSMsg(q), nil
}
func TestUnknownResolverCacheProbeAndNestedAdmission(t *testing.T) {
	r := &opaqueDNS{}
	if _, err := CachedDNS(t.Context(), r, DNSQuestion{}); !errors.Is(err, ErrDNSCacheMiss) || r.calls != 0 {
		t.Fatalf("opaque cache probe: calls=%d err=%v", r.calls, err)
	}
	limit := semaphore.NewSemaphore(1)
	ctx := WithDNSQueryLimiter(t.Context(), limit)
	if _, err := RawDNS(ctx, r, DNSQuestion{}); err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 || !limit.TryAcquire(1) {
		t.Fatalf("query did not release its permit: calls=%d", r.calls)
	}
	limit.Release(1)
}
func TestDNSAdmissionPreservesContextAndCancellation(t *testing.T) {
	type key struct{}
	limit := semaphore.NewSemaphore(1)
	if err := limit.Acquire(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	defer limit.Release(1)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), key{}, "request"))
	cancel()
	ctx = WithDNSQueryLimiter(ctx, limit)
	if _, _, err := AcquireDNSQuery(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled admission=%v", err)
	}
	if ctx.Value(key{}) != "request" {
		t.Fatal("lost request values")
	}
}

func TestDNSRefreshLeavesCacheOnlyProbe(t *testing.T) {
	probe := WithDNSCacheOnly(t.Context())
	query, limiter, err := AcquireDNSQuery(probe)
	if err != nil || limiter != nil || DNSCacheOnly(query) || !DNSCacheOnly(probe) {
		t.Fatalf("refresh/probe context: err=%v", err)
	}
}
