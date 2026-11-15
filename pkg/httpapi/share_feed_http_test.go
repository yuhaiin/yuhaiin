package httpapi

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
)

type fakeShareFeedSource struct {
	mu       sync.Mutex
	recorded []int64
}

func (f *fakeShareFeedSource) ResolveShareFeed(_ context.Context, token string) (string, contractsubscription.ShareFeedDocument, bool, error) {
	if token != "good" {
		return "", contractsubscription.ShareFeedDocument{}, false, nil
	}
	return "feed", contractsubscription.ShareFeedDocument{Version: 1, Name: "f"}, true, nil
}

func (f *fakeShareFeedSource) RecordShareFeedAccess(_ context.Context, id string, _, count int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, count)
	return nil
}

func serveShareFeed(handler http.Handler, remote, token string, secure bool) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.Handle(ShareFeedRoute, handler)
	r := httptest.NewRequest(http.MethodGet, "/share/"+token, nil)
	r.RemoteAddr = remote
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestShareFeedHandler(t *testing.T) {
	source := &fakeShareFeedSource{}
	handler := NewShareFeedHandler(source).(*shareFeedHandler)
	now := time.Unix(1000, 0)
	handler.now = func() time.Time { return now }

	if w := serveShareFeed(handler, "192.0.2.1:1000", "good", false); w.Code != http.StatusForbidden {
		t.Fatalf("plain HTTP from a remote peer = %d", w.Code)
	}
	w := serveShareFeed(handler, "192.0.2.1:1000", "good", true)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != contractsubscription.ShareFeedContentType || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("feed response = %d %v %s", w.Code, w.Header(), w.Body)
	}
	if w := serveShareFeed(handler, "127.0.0.1:1000", "good", false); w.Code != http.StatusOK {
		t.Fatalf("loopback reverse proxy = %d", w.Code)
	}
	if w := serveShareFeed(handler, "[::1]:1000", "bad", false); w.Code != http.StatusNotFound {
		t.Fatalf("unknown token = %d", w.Code)
	}

	// Access is written once per interval; later fetches are carried over.
	now = now.Add(shareFeedAccessFlush)
	if w := serveShareFeed(handler, "127.0.0.1:1000", "good", false); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	source.mu.Lock()
	recorded := append([]int64(nil), source.recorded...)
	source.mu.Unlock()
	if len(recorded) != 2 || recorded[0] != 1 || recorded[1] != 2 {
		t.Fatalf("recorded access = %v", recorded)
	}

	limited := false
	for range 20 {
		if serveShareFeed(handler, "198.51.100.7:1000", "bad", true).Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("one peer is not rate limited")
	}
	if w := serveShareFeed(handler, "203.0.113.9:1000", "good", true); w.Code != http.StatusOK {
		t.Fatalf("another peer was limited: %d", w.Code)
	}
}
