package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// One bounded worker per enabled gateway performs health probes. Policy changes
// cancel it before releasing its transport pools.
func (e *Engine) startHealth() {
	if !e.config.Enabled {
		return
	}
	needed := false
	for _, u := range e.upstreams {
		needed = needed || u.config.HealthPath != ""
	}
	if !needed {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.healthCancel = cancel
	e.healthWG.Go(func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		last := make(map[string]time.Time)
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				for id, u := range e.upstreams {
					if u.config.HealthPath == "" || now.Sub(last[id]) < durationMS(u.config.HealthIntervalMS, 10*time.Second) {
						continue
					}
					last[id] = now
					for _, b := range u.backends {
						if ctx.Err() != nil {
							return
						}
						e.probeBackend(ctx, u, b)
					}
				}
			}
		}
	})
}
func (e *Engine) probeBackend(ctx context.Context, u *upstream, b *backend) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw := b.url.Clone()
	raw.Path = u.config.HealthPath
	raw.RawPath = ""
	raw.RawQuery = ""
	request, err := http.NewRequestWithContext(netapi.WithContext(ctx), http.MethodHead, raw.String(), nil)
	if err != nil {
		u.recordHealth(b, true)
		return
	}
	port := raw.Port()
	if port == "" {
		port = "80"
		if raw.Scheme == "https" {
			port = "443"
		}
	}
	address, err := netapi.ParseAddress("tcp", net.JoinHostPort(raw.Hostname(), port))
	if err != nil {
		u.recordHealth(b, true)
		return
	}
	s, err := e.selectOutbound(request.Context(), address, u.config.Outbound)
	if err != nil {
		u.recordHealth(b, true)
		return
	}
	tr, release, err := e.pool.borrow(s, raw.Scheme+"://"+raw.Host, u.config)
	if err != nil {
		u.recordHealth(b, true)
		return
	}
	defer release()
	response, err := tr.RoundTrip(request)
	if err != nil {
		u.recordHealth(b, true)
		return
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	u.recordHealth(b, response.StatusCode < 200 || response.StatusCode >= 400)
}

func retryable(r *http.Request) bool {
	switch r.Method {
	case "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
		return r.Body == nil || r.Body == http.NoBody || r.GetBody != nil
	}
	return false
}

func roundTripWithRetry(tr *http.Transport, r *http.Request, retries int) (*http.Response, error) {
	response, err := tr.RoundTrip(r)
	for attempt := 0; err != nil && attempt < retries && retryable(r) && r.Context().Err() == nil; attempt++ {
		next := r.Clone(r.Context())
		if r.Body != nil && r.Body != http.NoBody {
			next.Body, err = r.GetBody()
			if err != nil {
				return nil, err
			}
		}
		response, err = tr.RoundTrip(next)
	}
	return response, err
}
