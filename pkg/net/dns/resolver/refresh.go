package resolver

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const backgroundRefreshLimit = 4

// Refresh work is optional: return stale answers without queueing goroutines when
// busy. A completed failure does not delay the next lookup's refresh attempt.
func (c *client) refresh(ctx context.Context, req netapi.DNSQuestion, key string) {
	if c.refreshContext.Err() != nil {
		return
	}
	if _, loaded := c.refreshBackground.LoadOrStore(key, struct{}{}); loaded {
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

		if _, err := c.queryWithMetrics(ctx, req); err != nil && c.refreshContext.Err() == nil {
			log.Error("refresh domain background failed", "req", req, "err", err)
		}
	}()
}
