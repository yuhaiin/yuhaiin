package connectip

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCloudflareHTTP2Headers(t *testing.T) {
	var captured *http.Request
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		captured = r
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	req, err := NewRequest(context.Background(), "https://cloudflareaccess.com/")
	if err != nil {
		t.Fatal(err)
	}
	conn, resp, err := NewCloudflareHTTP2ClientConn(rt).Dial(req)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if resp.StatusCode != http.StatusOK || captured == nil {
		t.Fatal("HTTP/2 CONNECT did not succeed")
	}
	if captured.Method != http.MethodConnect || captured.Header.Get("Cf-Connect-Proto") != "cf-connect-ip" ||
		captured.Header.Get("Pq-Enabled") != "false" ||
		captured.Header.Get("Capsule-Protocol") != "" {
		t.Fatalf("invalid Cloudflare CONNECT headers: %v", captured.Header)
	}
	if captured.Host != "cloudflareaccess.com:443" {
		t.Fatalf("wrong authority: %s", captured.Host)
	}
}

func TestStreamBufferClose(t *testing.T) {
	b := NewStreamBuffer()
	if n, err := b.Write([]byte("packet")); err != nil || n != 6 {
		t.Fatalf("write=%d %v", n, err)
	}
	got := make([]byte, 6)
	if n, err := b.Read(got); err != nil || n != 6 {
		t.Fatalf("read=%d %v", n, err)
	}
	if string(got) != "packet" {
		t.Fatalf("got %q", got)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(got); err != io.EOF {
		t.Fatalf("closed read: %v", err)
	}
}
