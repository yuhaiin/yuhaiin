package latency

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func uploadTLS(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *tls.Config) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return server, &tls.Config{RootCAs: pool}
}
func uploadRequest(url string) contract.SpeedTestRequest {
	return contract.SpeedTestRequest{URL: url, Direction: "upload", AllowUpload: true, MaxBytes: 8192, DurationMS: 1000, TimeoutMS: 2000}
}
func advertiseUpload(w http.ResponseWriter) {
	w.Header().Set(UploadProtocolHeader, UploadProtocolVersion)
	w.Header().Set("Content-Type", "application/json")
}
func TestUploadThroughCandidateAndAcknowledgedBudget(t *testing.T) {
	var heads, posts atomic.Int32
	server, config := uploadTLS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(UploadProtocolHeader) != UploadProtocolVersion {
			t.Error("missing upload handshake")
		}
		advertiseUpload(w)
		if r.Method == http.MethodHead {
			heads.Add(1)
			return
		}
		posts.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("invalid upload request")
		}
		n, err := io.Copy(io.Discard, io.LimitReader(r.Body, 8193))
		if err != nil || n != 8192 {
			t.Errorf("upload bytes=%d error=%v", n, err)
		}
		data, err := json.Marshal(UploadAcknowledgement{Version: 1, ReceivedBytes: n})
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(data)
	})
	proxy := new(measurementProxy)
	m, err := measureUpload(t.Context(), proxy, uploadRequest(server.URL), config)
	if err != nil || !m.OK || m.Direction != "upload" || m.Bytes != 8192 || m.UploadMbps <= 0 || m.DownloadMbps != 0 || m.Samples != 1 || heads.Load() != 1 || posts.Load() != 1 || proxy.calls.Load() != 2 {
		t.Fatalf("measurement=%+v heads=%d posts=%d dials=%d error=%v", m, heads.Load(), posts.Load(), proxy.calls.Load(), err)
	}
}
func TestUploadRequiresConsentAndAdvertisedEndpoint(t *testing.T) {
	for _, behavior := range []string{"consent", "untrusted", "no_advertisement", "head_redirect", "head_business_error"} {
		t.Run(behavior, func(t *testing.T) {
			var posts atomic.Int32
			server, config := uploadTLS(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
					t.Error("unexpected upload")
				}
				switch behavior {
				case "no_advertisement":
				case "head_redirect":
					w.Header().Set("Location", "https://redirect.invalid")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "head_business_error":
					advertiseUpload(w)
					w.WriteHeader(http.StatusForbidden)
				default:
					advertiseUpload(w)
				}
			})
			request := uploadRequest(server.URL)
			proxy := new(measurementProxy)
			if behavior == "consent" {
				request.AllowUpload = false
			}
			if behavior == "untrusted" {
				config = nil
			}
			m, err := measureUpload(t.Context(), proxy, request, config)
			if err == nil || m.OK || posts.Load() != 0 || proxy.calls.Load() > 1 {
				t.Fatalf("accepted unsafe test: %+v %v", m, err)
			}
			if behavior == "consent" && proxy.calls.Load() != 0 {
				t.Fatal("contacted endpoint without upload consent")
			}
		})
	}
}
func TestUploadRejectsUnprovenAcknowledgementsAndNeverReplays(t *testing.T) {
	for _, behavior := range []string{"wrong_bytes", "wrong_version", "duplicate", "unknown", "malformed", "oversize", "compressed", "non_json", "post_redirect", "post_error", "early_ack", "disconnect"} {
		t.Run(behavior, func(t *testing.T) {
			var posts atomic.Int32
			server, config := uploadTLS(t, func(w http.ResponseWriter, r *http.Request) {
				advertiseUpload(w)
				if r.Method == http.MethodHead {
					return
				}
				posts.Add(1)
				if behavior == "disconnect" {
					c, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = c.Close()
					return
				}
				n := int64(0)
				if behavior != "early_ack" {
					n, _ = io.Copy(io.Discard, r.Body)
				}
				switch behavior {
				case "wrong_bytes":
					n++
				case "wrong_version":
					_, _ = w.Write([]byte(`{"version":2,"receivedBytes":8192}`))
					return
				case "duplicate":
					_, _ = w.Write([]byte(`{"version":1,"version":1,"receivedBytes":8192}`))
					return
				case "unknown":
					_, _ = w.Write([]byte(`{"version":1,"receivedBytes":8192,"extra":true}`))
					return
				case "malformed":
					_, _ = w.Write([]byte(`{"version":`))
					return
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat(" ", MaxUploadAcknowledgementBytes+1)))
					return
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "non_json":
					w.Header().Set("Content-Type", "text/plain")
				case "post_redirect":
					w.Header().Set("Location", serverURLPlaceholder)
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				case "post_error":
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				data, _ := json.Marshal(UploadAcknowledgement{Version: 1, ReceivedBytes: n})
				_, _ = w.Write(data)
			})
			proxy := new(measurementProxy)
			m, err := measureUpload(t.Context(), proxy, uploadRequest(server.URL), config)
			if err == nil || m.OK || posts.Load() != 1 || proxy.calls.Load() != 2 {
				t.Fatalf("measurement=%+v posts=%d dials=%d error=%v", m, posts.Load(), proxy.calls.Load(), err)
			}
		})
	}
}

const serverURLPlaceholder = "https://redirect.invalid/never-follow"

func TestUploadCancellationClosesCandidate(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server, config := uploadTLS(t, func(w http.ResponseWriter, r *http.Request) {
		advertiseUpload(w)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-release
	})
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := measureUpload(ctx, new(measurementProxy), uploadRequest(server.URL), config)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled upload remained blocked")
	}
}
func TestUploadBodyBoundedEOFAndCancellation(t *testing.T) {
	body := &uploadBody{ctx: t.Context(), limit: 1024, duration: time.Second}
	buffer := make([]byte, 4096)
	n, err := body.Read(buffer)
	if n != 1024 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := body.Read(buffer); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal(n, err)
	}
	_, n64, finished := body.snapshot()
	if n64 != 1024 || !finished {
		t.Fatal(n64, finished)
	}
	duration := &uploadBody{ctx: t.Context(), start: time.Now().Add(-time.Second), limit: 8192, duration: time.Millisecond}
	if n, err := duration.Read(buffer); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal(n, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cancelled := &uploadBody{ctx: ctx, limit: 8192, duration: time.Second}
	if _, err := cancelled.Read(buffer); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func BenchmarkUploadStreamingBody(b *testing.B) {
	for _, size := range []int64{1 << 20, 16 << 20, 64 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			buffer := make([]byte, 32<<10)
			b.ReportAllocs()
			b.SetBytes(size)
			for b.Loop() {
				body := &uploadBody{ctx: b.Context(), limit: size, duration: 15 * time.Second}
				n, err := io.CopyBuffer(io.Discard, body, buffer)
				if err != nil || n != size {
					b.Fatal(n, err)
				}
			}
		})
	}
}
