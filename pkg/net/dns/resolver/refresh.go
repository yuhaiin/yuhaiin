package resolver

import (
	"context"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
	backgroundRefreshLimit = 4
	refreshRetryInitial    = 5 * time.Second
	refreshRetryMaximum    = time.Minute
)

type refreshFailure struct {
	retryAt time.Time
	delay   time.Duration
}

// Refresh work is optional: return stale answers without queueing goroutines when
// offline or busy. New questions still query immediately.
func (c *client) refresh(ctx context.Context, req netapi.DNSQuestion, key string) {
	if c.refreshContext.Err() != nil {
		return
	}
	if _, loaded := c.refreshBackground.LoadOrStore(key, struct{}{}); loaded {
		return
	}

	// Read cooldown only after reserving the key: a preceding refresh may have
	// failed between a stale lookup and this reservation.
	failure, _ := c.refreshFailures.Load(key)
	if time.Now().Before(failure.retryAt) {
		c.refreshBackground.Delete(key)
		return
	}
	select {
	case c.refreshSlots <- struct{}{}:
	default:
		c.refreshBackground.Delete(key)
		return
	}

	go func() {
		defer c.refreshBackground.Delete(key)
		defer func() { <-c.refreshSlots }()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), configuration.ResolverTimeout)
		defer cancel()
		stop := context.AfterFunc(c.refreshContext, cancel)
		defer stop()
		if c.refreshContext.Err() != nil {
			return
		}

		_, err := c.queryWithMetrics(ctx, req)
		if err == nil {
			c.refreshFailures.Delete(key)
			return
		}
		if c.refreshContext.Err() != nil {
			return
		}
		delay := refreshRetryInitial
		if failure.delay > 0 {
			delay = min(failure.delay*2, refreshRetryMaximum)
		}
		c.refreshFailures.Add(key, refreshFailure{retryAt: time.Now().Add(delay), delay: delay})
		log.Error("refresh domain background failed", "req", req, "err", err)
	}()
}
