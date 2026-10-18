package connectip

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

func TestHTTP3DialCancelsWhileWaitingForResponse(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	tlsConfig := certServer.TLS.Clone()
	certServer.Close()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	entered := make(chan struct{})
	server := &http3.Server{TLSConfig: tlsConfig, EnableDatagrams: true, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	})}
	defer server.Close()
	go func() { _ = server.Serve(socket) }()
	transport := &quic.Transport{Conn: mustClientSocket(t)}
	defer transport.Close()
	qc, err := transport.Dial(t.Context(), socket.LocalAddr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = qc.CloseWithError(0, "") }()
	rt := &http3.Transport{EnableDatagrams: true}
	defer rt.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, err := NewRequest(ctx, "https://proxy.example/")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		c, _, err := NewClientConn(rt.NewClientConn(qc)).Dial(req)
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Dial ignored cancellation while reading response")
	}
}

func mustClientSocket(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
