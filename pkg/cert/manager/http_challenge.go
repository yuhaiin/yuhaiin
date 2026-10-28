package manager

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
)

type httpChallengeKey struct{ gateway, domain, token string }
type httpChallengeValue struct {
	response string
	expires  time.Time
}

// HTTPChallenges is mounted only on an administrator-enabled existing HTTP
// Gateway. It never binds a port or changes the gateway's listener configuration.
type HTTPChallenges struct {
	mu        sync.Mutex
	pending   map[httpChallengeKey]httpChallengeValue
	available func(string) bool
}

func NewHTTPChallenges(available func(string) bool) *HTTPChallenges {
	return &HTTPChallenges{pending: map[httpChallengeKey]httpChallengeValue{}, available: available}
}

func validToken(token string) bool {
	if len(token) < 22 || len(token) > 256 {
		return false
	}
	for _, r := range token {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func (h *HTTPChallenges) Present(ctx context.Context, gateway, domain, token, response string) (func(), error) {
	deadline, ok := ctx.Deadline()
	if !ok || !contract.ValidID(gateway) || !contract.ValidDomain(domain, false) || time.Until(deadline) > 10*time.Minute || time.Until(deadline) <= 0 || !validToken(token) || !strings.HasPrefix(response, token+".") || len(response) > 1024 {
		return nil, errors.New("invalid bounded HTTP-01 authorization")
	}
	if h.available == nil || !h.available(gateway) {
		return nil, errors.New("HTTP-01 gateway must explicitly enable challenge handling on port 80")
	}
	key := httpChallengeKey{gateway, domain, token}
	h.mu.Lock()
	defer h.mu.Unlock()
	for key, value := range h.pending {
		if time.Now().After(value.expires) {
			delete(h.pending, key)
		}
	}
	if len(h.pending) >= 128 {
		return nil, errors.New("HTTP-01 challenge limit reached")
	}
	if _, exists := h.pending[key]; exists {
		return nil, errors.New("HTTP-01 challenge is already active")
	}
	h.pending[key] = httpChallengeValue{response, deadline}
	remove := sync.OnceFunc(func() { h.mu.Lock(); delete(h.pending, key); h.mu.Unlock() })
	stop := context.AfterFunc(ctx, remove)
	return func() { stop(); remove() }, nil
}

// Serve returns false for ordinary gateway traffic. A reserved challenge path
// is always handled here, with an exact gateway/Host/token match and no redirects.
func (h *HTTPChallenges) Serve(gateway string, w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	host := r.Host
	if strings.Contains(host, ":") {
		var err error
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			http.NotFound(w, r)
			return true
		}
	}
	token := strings.TrimPrefix(r.URL.Path, prefix)
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.URL.RawPath != "" || !validToken(token) {
		http.NotFound(w, r)
		return true
	}
	h.mu.Lock()
	value, ok := h.pending[httpChallengeKey{gateway, strings.ToLower(host), token}]
	h.mu.Unlock()
	if !ok || !time.Now().Before(value.expires) {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(value.response))
	return true
}
