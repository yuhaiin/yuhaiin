package resolver

import (
	"context"
	"errors"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
	queryRetryInitial = time.Second
	queryRetryMaximum = 5 * time.Second
)

type queryFailure struct {
	err     error
	retryAt time.Time
	delay   time.Duration
}

// The singleflight caller owns this check and publishes the failure before
// releasing its key, so sequential misses cannot bypass failure backoff.
func (c *client) queryUncached(ctx context.Context, req netapi.DNSQuestion, key string) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	failure, _ := c.queryFailures.Load(key)
	if time.Now().Before(failure.retryAt) {
		return nil, failure.err
	}
	msg, err := c.queryWithMetrics(ctx, req)
	if err == nil {
		c.queryFailures.Delete(key)
		return msg, nil
	}
	// Explicit cancellation is not evidence of an unavailable upstream. Query
	// timeouts are failures and must back off, including caller deadline expiry.
	if errors.Is(err, context.Canceled) || ctx.Err() == context.Canceled || c.refreshContext.Err() != nil {
		return nil, err
	}
	delay := queryRetryInitial
	if failure.delay > 0 {
		delay = min(failure.delay*2, queryRetryMaximum)
	}
	c.queryFailures.Add(key, queryFailure{err: err, retryAt: time.Now().Add(delay), delay: delay})
	return nil, err
}

func (c *client) clearQueryFailures(domain string) {
	var keys []string
	c.queryFailures.Range(func(key string, _ queryFailure) bool {
		name, _, found := strings.CutLast(key, ":")
		if found && name != "" && canonicalCacheDomain(name) == domain {
			keys = append(keys, key)
		}
		return true
	})
	for _, key := range keys {
		c.queryFailures.Delete(key)
	}
}
