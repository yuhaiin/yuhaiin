package auth

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuditHTTPSRequiresTrustAndRejectsRedirectsWithoutLoggingProofs(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.Header.Get("Authorization") != "Bearer private-proof" {
			t.Error("missing authentication")
		}
		var body struct {
			InstanceID string        `json:"instanceId"`
			Events     []AuditRecord `json:"events"`
		}
		if err := json.UnmarshalRead(r.Body, &body); err != nil || body.InstanceID != "instance" || len(body.Events) != 1 || body.Events[0].ID != "9007199254740993" {
			t.Errorf("body=%+v err=%v", body, err)
		}
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "https://other.example/private-proof")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/reject":
			w.WriteHeader(500)
			_, _ = io.WriteString(w, "private-proof remote-body")
		default:
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	cfg := auditConfiguration{InstanceID: "instance", Revision: 1, MaxEvents: 1000, OutboxLimit: 64, Transport: "https", ForwardEnabled: true, Endpoint: server.URL, token: "private-proof"}
	records := []AuditRecord{{ID: "9007199254740993", Event: "test.updated"}}
	if err := (networkAuditSender{}).send(t.Context(), cfg, records); err == nil {
		t.Fatal("accepted untrusted TLS certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	sender := networkAuditSender{roots: roots}
	for _, path := range []string{"/", "/redirect", "/reject"} {
		cfg.Endpoint = server.URL + path
		err := sender.send(t.Context(), cfg, records)
		if path == "/" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || auditDeliveryReason(err) != "delivery_http_rejected" || strings.Contains(err.Error(), "private-proof") {
			t.Fatalf("unsafe rejection %v", err)
		}
	}
	if received.Load() != 3 {
		t.Fatal("untrusted request or redirected request was sent")
	}
}
func TestAuditSyslogTLSOctetFraming(t *testing.T) {
	// Reuse a test TLS certificate, while keeping the production sender pinned to
	// normal system trust. Trust injection is private to this package's tests.
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certServer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: certServer.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		for range 2 {
			prefix, err := reader.ReadString(' ')
			if err != nil {
				result <- err
				return
			}
			count, err := strconv.Atoi(strings.TrimSuffix(prefix, " "))
			if err != nil || count > 64<<10 {
				result <- fmt.Errorf("bad frame %q", prefix)
				return
			}
			payload := make([]byte, count)
			if _, err = io.ReadFull(reader, payload); err != nil {
				result <- err
				return
			}
			if !strings.HasPrefix(string(payload), "<134>1 ") || !strings.Contains(string(payload), `"instanceId":"instance"`) || !strings.Contains(string(payload), `"actorId":"監査"`) {
				result <- fmt.Errorf("invalid frame %q", payload)
				return
			}
		}
		result <- nil
	}()
	cfg := auditConfiguration{Revision: 1, MaxEvents: 1000, OutboxLimit: 64, Transport: "syslog-tls", ForwardEnabled: true, Endpoint: "tls://" + listener.Addr().String(), InstanceID: "instance"}
	records := []AuditRecord{{ID: "1", OccurredAt: time.Now().Unix(), ActorID: "監査"}, {ID: "2", OccurredAt: time.Now().Unix(), ActorID: "監査"}}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := (networkAuditSender{roots: roots}).send(ctx, cfg, records); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

var _ net.Conn = (*tls.Conn)(nil)
