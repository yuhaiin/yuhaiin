package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsExpectedRequestRelayError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", want: true},
		{name: "EOF", err: io.EOF, want: true},
		{name: "wrapped EOF", err: fmt.Errorf("read: %w", io.EOF), want: true},
		{name: "closed pipe", err: io.ErrClosedPipe, want: true},
		{name: "closed connection", err: net.ErrClosed, want: true},
		{name: "canceled context", err: context.Canceled, want: true},
		{name: "wrapped cancel", err: fmt.Errorf("request: %w", context.Canceled), want: true},
		{name: "client disconnected", err: errors.New("client disconnected"), want: true},
		{name: "body closed by handler", err: errors.New("body closed by handler"), want: true},
		{name: "stream canceled", err: errors.New("stream error: stream ID 1; CANCEL"), want: true},
		{name: "network error", err: errors.New("connection refused")},
		{name: "deadline exceeded", err: context.DeadlineExceeded},
		{name: "unrelated body error", err: errors.New("body closed unexpectedly")},
		{name: "wrapped handler close", err: fmt.Errorf("upstream failure: %w", errors.New("body closed by handler"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExpectedRequestRelayError(tt.err); got != tt.want {
				t.Errorf("isExpectedRequestRelayError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

type handlerClosedBody struct {
	started chan struct{}
	closed  chan struct{}
	stopped chan struct{}
}

func (b *handlerClosedBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.closed
	close(b.stopped)
	return 0, errors.New("body closed by handler")
}

func (b *handlerClosedBody) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func TestServeHTTPReleasesRequestRelayWhenResponseEnds(t *testing.T) {
	body := &handlerClosedBody{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
		stopped: make(chan struct{}),
	}
	t.Cleanup(func() { _ = body.Close() })

	server := &Server{
		closedCtx: context.Background(),
		connChan:  make(chan net.Conn),
	}
	request := httptest.NewRequest(http.MethodConnect, "http://localhost", body)
	handlerDone := make(chan struct{})
	go func() {
		server.ServeHTTP(httptest.NewRecorder(), request)
		close(handlerDone)
	}()

	var peer net.Conn
	select {
	case peer = <-server.connChan:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/2 handler did not publish the tunnel")
	}
	defer peer.Close()

	select {
	case <-body.started:
	case <-time.After(3 * time.Second):
		t.Fatal("request relay did not begin reading the body")
	}
	// Closing the tunneled response lets ServeHTTP return while the request
	// relay is still reading. net/http then closes r.Body to unblock it.
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("ServeHTTP did not return after the tunnel closed")
	}

	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-body.stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("request body read remained blocked after handler exit")
	}
}
