package httpapi

import (
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/netip"
	"sync"
	"time"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"golang.org/x/time/rate"
)

// ShareFeedRoute serves share feeds on the management listener. The token in
// the path is the only credential, so the route bypasses management auth.
const ShareFeedRoute = "GET /share/{token}"

// ShareFeedSource is the storage a share feed handler reads.
type ShareFeedSource interface {
	ResolveShareFeed(context.Context, string) (string, contractsubscription.ShareFeedDocument, bool, error)
	RecordShareFeedAccess(context.Context, string, int64, int64) error
}

const (
	maxShareFeedToken = 128
	// Statistics are written at most once per interval per feed so anonymous
	// requests cannot turn into a stream of database writes.
	shareFeedAccessFlush = time.Minute
	shareFeedPeerIdle    = 10 * time.Minute
)

type shareFeedHandler struct {
	source ShareFeedSource
	now    func() time.Time
	// global bounds the token scans all anonymous peers can cause together.
	global *rate.Limiter

	mu     sync.Mutex
	peers  map[netip.Addr]*shareFeedPeer
	access map[string]*shareFeedAccess
	swept  time.Time
}

type shareFeedPeer struct {
	limiter *rate.Limiter
	seen    time.Time
}

type shareFeedAccess struct {
	written time.Time
	pending int64
	last    int64
}

// NewShareFeedHandler serves share feed documents to subscribers.
func NewShareFeedHandler(source ShareFeedSource) http.Handler {
	return &shareFeedHandler{
		source: source,
		now:    time.Now,
		global: rate.NewLimiter(20, 40),
		peers:  map[netip.Addr]*shareFeedPeer{},
		access: map[string]*shareFeedAccess{},
	}
}

func (h *shareFeedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid peer", http.StatusForbidden)
		return
	}
	addr := peer.Addr().Unmap()
	// The document carries node credentials. Like the management API, serve
	// it only over TLS or to a loopback reverse proxy.
	if r.TLS == nil && !addr.IsLoopback() {
		http.Error(w, "share feeds require HTTPS", http.StatusForbidden)
		return
	}
	if !h.allow(addr) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	token := r.PathValue("token")
	if token == "" || len(token) > maxShareFeedToken {
		http.NotFound(w, r)
		return
	}
	id, document, ok, err := h.source.ResolveShareFeed(r.Context(), token)
	if err != nil {
		log.Error("resolve share feed failed", "err", err)
		http.Error(w, "share feed is unavailable", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := json.Marshal(document)
	if err != nil {
		log.Error("encode share feed failed", "err", err)
		http.Error(w, "share feed is unavailable", http.StatusInternalServerError)
		return
	}
	h.record(r.Context(), id)
	w.Header().Set("Content-Type", contractsubscription.ShareFeedContentType)
	_, _ = w.Write(body)
}

func (h *shareFeedHandler) allow(addr netip.Addr) bool {
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if now.Sub(h.swept) > shareFeedPeerIdle {
		for key, peer := range h.peers {
			if now.Sub(peer.seen) > shareFeedPeerIdle {
				delete(h.peers, key)
			}
		}
		h.swept = now
	}
	peer := h.peers[addr]
	if peer == nil {
		// A subscriber refreshes a few times an hour; allow short bursts from
		// several feeds behind one address.
		peer = &shareFeedPeer{limiter: rate.NewLimiter(rate.Every(6*time.Second), 10)}
		h.peers[addr] = peer
	}
	peer.seen = now
	return peer.limiter.AllowN(now, 1) && h.global.AllowN(now, 1)
}

func (h *shareFeedHandler) record(ctx context.Context, id string) {
	now := h.now()
	h.mu.Lock()
	entry := h.access[id]
	if entry == nil {
		entry = &shareFeedAccess{}
		h.access[id] = entry
	}
	entry.pending++
	entry.last = now.Unix()
	if now.Sub(entry.written) < shareFeedAccessFlush {
		h.mu.Unlock()
		return
	}
	pending, last := entry.pending, entry.last
	entry.pending, entry.written = 0, now
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := h.source.RecordShareFeedAccess(ctx, id, last, pending); err != nil {
		log.Warn("record share feed access failed", "err", err)
	}
}
