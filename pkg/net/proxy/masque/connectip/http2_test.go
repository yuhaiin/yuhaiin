package connectip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
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

func TestStreamBufferBoundsLargeWrite(t *testing.T) {
	b := NewStreamBuffer()
	defer b.Close()
	if err := b.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := b.Write(bytes.Repeat([]byte{1}, 3*maxStreamBuffer))
	if n != maxStreamBuffer || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("large write = %d, %v; want bounded partial write and deadline", n, err)
	}
}

func TestStreamBufferWrapAndCloseBlockedWriter(t *testing.T) {
	b := NewStreamBuffer()
	defer b.Close()
	first := bytes.Repeat([]byte{1}, maxStreamBuffer-100)
	if _, err := b.Write(first); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(first)-100)
	if _, err := io.ReadFull(b, got); err != nil || !bytes.Equal(got, first[:len(got)]) {
		t.Fatalf("first read: %v", err)
	}
	second := bytes.Repeat([]byte{2}, 1000)
	if _, err := b.Write(second); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, 1100)
	if _, err := io.ReadFull(b, got); err != nil || !bytes.Equal(got, append(first[:100:100], second...)) {
		t.Fatalf("wrapped read: %v", err)
	}
	if _, err := b.Write(make([]byte, maxStreamBuffer)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := b.Write([]byte{3}); done <- err }()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake blocked writer")
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
