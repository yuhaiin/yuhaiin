package route

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

func TestDownloadFailureDoesNotExposeSourceCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "server-response-secret")
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	target.User = url.UserPassword("username-secret", "password-secret")
	target.Path = "/path-secret"
	target.RawQuery = "token=query-secret"
	d := NewDownloader(t.TempDir(), func() netapi.Proxy { return direct.Default })
	err = d.Download(t.Context(), target.String(), nil)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected actionable HTTP status: %v", err)
	}
	for _, marker := range []string{"username-secret", "password-secret", "path-secret", "query-secret", "server-response-secret"} {
		if strings.Contains(err.Error(), marker) {
			t.Fatal("download error exposed source credentials")
		}
	}
}

func TestCanceledDownloadDoesNotExposeSourceCredentials(t *testing.T) {
	target := "http://username-secret:password-secret@127.0.0.1:1/path-secret?token=query-secret"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	d := NewDownloader(t.TempDir(), func() netapi.Proxy { return direct.Default })
	err := d.Download(ctx, target, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation classification was lost: %v", err)
	}
	for _, marker := range []string{"username-secret", "password-secret", "path-secret", "query-secret"} {
		if strings.Contains(err.Error(), marker) {
			t.Fatal("canceled download exposed source credentials")
		}
	}
}

func TestMissingSourceFileDoesNotExposePath(t *testing.T) {
	target := (&url.URL{Scheme: "file", Path: filepath.Join(t.TempDir(), "path-secret")}).String()
	d := NewDownloader(t.TempDir(), nil)
	_, err := d.GetReader(target)
	if !errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "path-secret") {
		t.Fatal("missing source must preserve its error class without disclosing its path")
	}
}

func TestDownloadTLSFailureDoesNotExposeSourceCredentials(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "private payload")
	}))
	defer server.Close()
	d := NewDownloader(t.TempDir(), func() netapi.Proxy { return direct.Default })
	err := d.Download(t.Context(), server.URL+"/path-secret?token=query-secret", nil)
	if err == nil || !strings.Contains(err.Error(), "TLS certificate verification failed") {
		t.Fatal("untrusted TLS source did not retain a useful error category")
	}
	if strings.Contains(err.Error(), "path-secret") || strings.Contains(err.Error(), "query-secret") {
		t.Fatal("TLS failure exposed source credentials")
	}
}

func TestDownloadFailureDoesNotWaitForResponseBody(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "untrusted response")
	}))
	defer server.Close()
	defer close(release)
	d := NewDownloader(t.TempDir(), func() netapi.Proxy { return direct.Default })
	result := make(chan error, 1)
	go func() { result <- d.Download(t.Context(), server.URL, nil) }()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatal("missing HTTP status")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("download waited for an untrusted error body")
	}
}

func TestDownloadClosesTemporaryTransport(t *testing.T) {
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "example.org\n")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()
	d := NewDownloader(t.TempDir(), func() netapi.Proxy { return direct.Default })
	if err := d.Download(t.Context(), server.URL, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("one-shot route download retained its HTTP connection")
	}
}
