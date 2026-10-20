package gateway

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// isStreamingResponse is deliberately response-based: an EventSource request
// does not have a special method, and any URL may return an SSE stream.
func isStreamingResponse(resp *http.Response) bool {
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return true
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	if contentType == "text/event-stream" {
		return true
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		(contentType == "application/grpc" || strings.HasPrefix(contentType, "application/grpc+"))
}

// proxyTimeout bounds response-header setup with the normal request timer.
// Long-lived streams switch to an optional inactivity timeout as soon as
// headers arrive. No timer keeps a connection alive after the handler exits.
type proxyTimeout struct {
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	requestTimer *time.Timer
	idleTimer    *time.Timer
	idlePeriod   time.Duration
	lastActivity time.Time
	body         io.ReadCloser
	closed       bool
}

func newProxyTimeout(parent context.Context, requestMS, idleMS int) *proxyTimeout {
	ctx, cancel := context.WithCancel(parent)
	t := &proxyTimeout{ctx: ctx, cancel: cancel, idlePeriod: durationMS(idleMS, 0)}
	if requestMS > 0 {
		t.requestTimer = time.AfterFunc(durationMS(requestMS, 0), cancel)
	}
	return t
}

func (t *proxyTimeout) stream(body io.ReadCloser) io.ReadCloser {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.requestTimer != nil {
		t.requestTimer.Stop()
		t.requestTimer = nil
	}
	if t.closed || t.idlePeriod == 0 {
		return body
	}
	t.body = body
	t.lastActivity = time.Now()
	t.idleTimer = time.AfterFunc(t.idlePeriod, t.expire)
	observed := &activityBody{ReadCloser: body, touch: t.touch}
	if writer, ok := body.(io.Writer); ok {
		return activityDuplexBody{activityBody: observed, writer: writer}
	}
	return observed
}

func (t *proxyTimeout) touch() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.idleTimer == nil {
		return
	}
	t.lastActivity = time.Now()
	t.idleTimer.Reset(t.idlePeriod)
}

func (t *proxyTimeout) expire() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	if remaining := t.idlePeriod - time.Since(t.lastActivity); remaining > 0 {
		t.idleTimer.Reset(remaining)
		t.mu.Unlock()
		return
	}
	t.closed = true
	body := t.body
	t.mu.Unlock()
	t.cancel()
	if body != nil {
		_ = body.Close() // Also wakes hijacked WebSocket copy loops.
	}
}

func (t *proxyTimeout) close() {
	t.mu.Lock()
	t.closed = true
	if t.requestTimer != nil {
		t.requestTimer.Stop()
	}
	if t.idleTimer != nil {
		t.idleTimer.Stop()
	}
	t.mu.Unlock()
	t.cancel()
}

// Keep the original body's optional io.Writer for 101 Upgrade responses.
type activityBody struct {
	io.ReadCloser
	touch func()
}

func (b *activityBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.touch()
	}
	return n, err
}

type activityDuplexBody struct {
	*activityBody
	writer io.Writer
}

func (b activityDuplexBody) Write(p []byte) (int, error) {
	n, err := b.writer.Write(p)
	if n > 0 {
		b.touch()
	}
	return n, err
}
