package netapi

import (
	"context"
	"errors"
	"net"
	"strings"

	"codeberg.org/miekg/dns"
)

// ErrDNSCacheMiss means that answering requires upstream work. It must not be
// returned as a DNS response or stored as an upstream failure.
var ErrDNSCacheMiss = errors.New("DNS answer is not cached")

// DNSCachedResolver runs the same policy, hosts and FakeIP transformations as
// Raw, but never waits for an upstream query. Stale answers may start a bounded
// background refresh. Messages support independent packing; shared records
// stay read-only. Normal Raw implementations admit upstream I/O with
// AcquireDNSQuery after deduplication, or forward through RawDNS.
// Resolvers without this optional interface are conservatively treated as misses.
type DNSCachedResolver interface {
	RawCached(context.Context, DNSQuestion) (*dns.Msg, error)
}

type DNSLookupFunc func(context.Context, Resolver, DNSQuestion) (*dns.Msg, error)

type dnsCacheOnlyKey struct{}

func DNSCacheOnly(ctx context.Context) bool {
	cached, _ := ctx.Value(dnsCacheOnlyKey{}).(bool)
	return cached
}

// WithDNSCacheOnly constrains ancillary lookups made while selecting a resolver.
func WithDNSCacheOnly(ctx context.Context) context.Context {
	if DNSCacheOnly(ctx) {
		return ctx
	}
	return context.WithValue(ctx, dnsCacheOnlyKey{}, true)
}

func CachedDNS(ctx context.Context, r Resolver, q DNSQuestion) (*dns.Msg, error) {
	cached, ok := r.(DNSCachedResolver)
	if !ok {
		return nil, ErrDNSCacheMiss
	}
	ctx = WithDNSCacheOnly(ctx)
	msg, err := cached.RawCached(ctx, q)
	if errors.Is(err, ErrDNSCacheMiss) {
		if store := GetContextOrNil(ctx); store != nil && errors.Is(store.ConnOptions().RouteIPError(), ErrDNSCacheMiss) {
			store.ConnOptions().routeCache = nil
		}
	}
	return msg, err
}

// CachedLookupIP is used while matching IP-based routing policy. If either
// required address family is missing, selection must be deferred rather than
// assuming an unresolved domain does not match an IP/GeoIP rule.
func CachedLookupIP(ctx context.Context, r Resolver, domain string, opts ...func(*LookupIPOption)) (*IPs, error) {
	opt := &LookupIPOption{}
	for _, apply := range opts {
		apply(opt)
	}
	result := &IPs{}
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if typ == dns.TypeA && opt.Mode == ResolverModePreferIPv6 || typ == dns.TypeAAAA && opt.Mode == ResolverModePreferIPv4 {
			continue
		}
		msg, err := CachedDNS(ctx, r, DNSQuestion{Name: strings.TrimSuffix(domain, ".") + ".", Qtype: typ, Qclass: dns.ClassINET})
		if err != nil {
			return nil, err
		}
		for _, rr := range msg.Answer {
			switch a := rr.(type) {
			case *dns.A:
				if typ == dns.TypeA {
					result.A = append(result.A, net.IP(a.Addr.AsSlice()))
				}
			case *dns.AAAA:
				if typ == dns.TypeAAAA {
					result.AAAA = append(result.AAAA, net.IP(a.Addr.AsSlice()))
				}
			}
		}
	}
	if result.Len() == 0 {
		return nil, &net.DNSError{Name: domain, Err: "no such host", IsNotFound: true}
	}
	return result, nil
}

// RawDNS also admits unknown resolver implementations, which cannot place the
// admission boundary after their own cache/singleflight lookup.
func RawDNS(ctx context.Context, r Resolver, q DNSQuestion) (*dns.Msg, error) {
	if _, ok := r.(DNSCachedResolver); !ok {
		queryCtx, limiter, err := AcquireDNSQuery(ctx)
		if err != nil {
			return nil, err
		}
		if limiter != nil {
			defer limiter.Release(1)
		}
		ctx = queryCtx
	}
	return r.Raw(ctx, q)
}

// DNSQueryLimiter limits actual upstream queries, not cache hits or singleflight
// waiters. The server separately bounds retained requests and response goroutines.
type DNSQueryLimiter interface {
	Acquire(context.Context, int64) error
	Release(int64)
}
type dnsQueryLimiterKey struct{}

func WithDNSQueryLimiter(ctx context.Context, limiter DNSQueryLimiter) context.Context {
	return context.WithValue(ctx, dnsQueryLimiterKey{}, limiter)
}

// AcquireDNSQuery is called inside the singleflight owner's function. Clear the
// limiter while doing upstream I/O: resolving that upstream's hostname must not
// recursively wait for a permit held by its parent query.
func AcquireDNSQuery(ctx context.Context) (context.Context, DNSQueryLimiter, error) {
	// A stale cache probe can schedule a real refresh. Its upstream bootstrap
	// lookups must be allowed to query, while the synchronous probe stays cache-only.
	if DNSCacheOnly(ctx) {
		ctx = context.WithValue(ctx, dnsCacheOnlyKey{}, false)
	}
	limiter, _ := ctx.Value(dnsQueryLimiterKey{}).(DNSQueryLimiter)
	if limiter == nil {
		return ctx, nil, nil
	}
	if err := limiter.Acquire(ctx, 1); err != nil {
		return ctx, nil, err
	}
	return context.WithValue(ctx, dnsQueryLimiterKey{}, nil), limiter, nil
}
