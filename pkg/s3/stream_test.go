package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

func localS3(t *testing.T, handler http.HandlerFunc) *S3 {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewS3(contractbackup.S3{EndpointURL: server.URL, Bucket: "backups", Region: "us-east-1", AccessKey: "fixture-access", SecretKey: "fixture-secret", StorageClass: "STANDARD"}, direct.Default)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestS3StreamsSignedObject(t *testing.T) {
	payload := bytes.Repeat([]byte("snapshot"), 1024)
	var uploads atomic.Int32
	client := localS3(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backups/state.db" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("missing signed path-style request")
		}
		switch r.Method {
		case http.MethodPut:
			if r.ContentLength != int64(len(payload)) || r.Header.Get("X-Amz-Storage-Class") != "STANDARD" {
				t.Error("upload length or storage class was lost")
			}
			data, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(data, payload) {
				t.Error("upload payload mismatch")
			}
			uploads.Add(1)
			w.Header().Set("ETag", `"fixture"`)
		case http.MethodGet:
			_, _ = w.Write(payload)
		}
	})
	if err := client.PutReader(t.Context(), bytes.NewReader(payload), int64(len(payload)), "state.db"); err != nil {
		t.Fatal(err)
	}
	var target bytes.Buffer
	n, err := client.Download(t.Context(), &target, "state.db", int64(len(payload)))
	if err != nil || n != int64(len(payload)) || !bytes.Equal(target.Bytes(), payload) || uploads.Load() != 1 {
		t.Fatalf("download mismatch: %d, %v", n, err)
	}
}

func TestS3DownloadCancellationAndLimits(t *testing.T) {
	t.Run("cancel headers", func(t *testing.T) {
		started := make(chan struct{}, 1)
		client := localS3(t, func(w http.ResponseWriter, r *http.Request) { started <- struct{}{}; <-r.Context().Done() })
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { _, err := client.Download(ctx, io.Discard, "state.db", 100); result <- err }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("request did not start")
		}
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("download did not cancel")
		}
	})
	t.Run("chunked oversize", func(t *testing.T) {
		client := localS3(t, func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "0123456789")
		})
		var target bytes.Buffer
		n, err := client.Download(t.Context(), &target, "state.db", 4)
		if err == nil || n != 4 || target.Len() != 4 {
			t.Fatalf("download limit not enforced: %d, %v", n, err)
		}
	})
	t.Run("broken body", func(t *testing.T) {
		client := localS3(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, "short")
		})
		if _, err := client.Download(t.Context(), io.Discard, "state.db", 100); err == nil {
			t.Fatal("truncated object accepted")
		}
	})
}

type zeroObject struct{}

func (zeroObject) ReadAt(p []byte, off int64) (int, error) { clear(p); return len(p), nil }

func TestS3MultipartBoundedAndAbort(t *testing.T) {
	for _, failure := range []string{"", "part", "complete", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			var parts, aborts, completions atomic.Int32
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client := localS3(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
					_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><UploadId>fixture-upload</UploadId></InitiateMultipartUploadResult>`)
				case r.Method == http.MethodPut:
					parts.Add(1)
					if r.ContentLength > partBytes {
						t.Error("part exceeds hard limit")
					}
					if failure == "part" {
						w.WriteHeader(http.StatusForbidden)
						_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code></Error>`)
						return
					}
					n, err := io.Copy(io.Discard, r.Body)
					if err != nil || n != r.ContentLength {
						t.Error("incomplete part")
					}
					if failure == "cancel" {
						cancel()
					}
					w.Header().Set("ETag", fmt.Sprintf(`"part-%d"`, parts.Load()))
				case r.Method == http.MethodPost:
					completions.Add(1)
					if failure == "complete" {
						w.WriteHeader(http.StatusForbidden)
						_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code></Error>`)
						return
					}
					_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><ETag>complete</ETag></CompleteMultipartUploadResult>`)
				case r.Method == http.MethodDelete:
					if r.Context().Err() != nil {
						t.Error("abort inherited cancelled context")
					}
					aborts.Add(1)
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected operation: %s", r.Method)
				}
			})
			err := client.PutReader(ctx, zeroObject{}, partBytes+73, "full.yhb")
			if failure == "" {
				if err != nil || parts.Load() != 2 || completions.Load() != 1 || aborts.Load() != 0 {
					t.Fatalf("multipart completion: %v, %d/%d/%d", err, parts.Load(), completions.Load(), aborts.Load())
				}
			} else if err == nil || aborts.Load() != 1 {
				t.Fatalf("failed multipart not aborted: %v, %d", err, aborts.Load())
			}
		})
	}
}

func TestS3RetryIsFiniteAndCancelledBeforeUpload(t *testing.T) {
	var attempts atomic.Int32
	client := localS3(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `<Error><Code>ServiceUnavailable</Code></Error>`)
	})
	if err := client.Put(t.Context(), []byte("snapshot"), "state.db"); err == nil || attempts.Load() != 3 {
		t.Fatalf("retry bound: %v, %d attempts", err, attempts.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.PutReader(ctx, zeroObject{}, MaxObjectBytes+1, "state.db"); err == nil {
		t.Fatal("unbounded object allowed")
	}
	if err := client.PutReader(ctx, zeroObject{}, 100, "state.db"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel before upload: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatal("cancelled upload sent traffic")
	}
}

func TestS3RejectsInvalidEndpointsAndUntrustedTLS(t *testing.T) {
	for _, endpoint := range []string{"file:///tmp/backup", "https://access:secret@example.com", "https://example.com?key=secret", "https://example.com/#secret"} {
		if client, err := NewS3(contractbackup.S3{EndpointURL: endpoint}, direct.Default); err == nil {
			_ = client.Close()
			t.Fatal("invalid endpoint accepted")
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted TLS server received authenticated request")
	}))
	defer server.Close()
	client, err := NewS3(contractbackup.S3{EndpointURL: server.URL, Bucket: "backups", AccessKey: "access", SecretKey: "secret"}, direct.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Put(t.Context(), []byte("private backup"), "state.db"); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}
