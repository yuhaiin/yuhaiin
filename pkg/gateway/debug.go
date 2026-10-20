package gateway

import (
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const maxDebugPathLength = 2048

type requestTrace struct {
	gatewayID     string
	gatewayName   string
	method        string
	host          string
	path          string
	contentLength int64
	body          *countedRequestBody
	writer        *traceResponseWriter
}

func newRequestTrace(gatewayID, gatewayName string, w http.ResponseWriter, r *http.Request) *requestTrace {
	trace := &requestTrace{
		gatewayID:     gatewayID,
		gatewayName:   gatewayName,
		method:        r.Method,
		host:          r.Host,
		path:          debugRequestPath(r),
		contentLength: r.ContentLength,
		writer:        &traceResponseWriter{ResponseWriter: w},
	}
	if r.Body != nil {
		trace.body = &countedRequestBody{ReadCloser: r.Body}
	}
	return trace
}

func debugRequestPath(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	path := r.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	if len(path) > maxDebugPathLength {
		return path[:maxDebugPathLength] + "…"
	}
	return path
}

func (t *requestTrace) finish(start time.Time) {
	if recovered := recover(); recovered != nil {
		t.writer.setDefaultStatus(http.StatusInternalServerError)
		t.writeLog(start)
		panic(recovered)
	}
	t.writer.setDefaultStatus(http.StatusOK)
	t.writeLog(start)
}

func (t *requestTrace) writeLog(start time.Time) {
	var requestBodyBytes int64
	if t.body != nil {
		requestBodyBytes = t.body.bytes.Load()
	}
	log.Info("gateway HTTP request",
		"gateway", t.gatewayName,
		"gateway_id", t.gatewayID,
		"method", t.method,
		"host", t.host,
		"path", t.path,
		"status", t.writer.status,
		"request_content_length", t.contentLength,
		"request_body_bytes_read", requestBodyBytes,
		"response_body_bytes_written", t.writer.bytes,
		"duration_ms", float64(time.Since(start))/float64(time.Millisecond),
	)
}

type countedRequestBody struct {
	io.ReadCloser
	bytes atomic.Int64
}

func (b *countedRequestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.bytes.Add(int64(n))
	}
	return n, err
}

// traceResponseWriter records response bytes and lets ResponseController reach
// the underlying writer for streaming and protocol upgrades.
type traceResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *traceResponseWriter) WriteHeader(status int) {
	if status >= http.StatusOK || status == http.StatusSwitchingProtocols {
		w.setDefaultStatus(status)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *traceResponseWriter) Write(p []byte) (int, error) {
	w.setDefaultStatus(http.StatusOK)
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *traceResponseWriter) setDefaultStatus(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *traceResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *traceResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	w.setDefaultStatus(http.StatusOK)
	return io.Copy(struct{ io.Writer }{w}, r)
}
