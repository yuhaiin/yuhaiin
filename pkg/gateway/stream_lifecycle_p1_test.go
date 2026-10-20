package gateway

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/coder/websocket"
)

func TestSSESurvivesRequestTimeoutOnHTTP1AndHTTP2(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			engine, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
				_, _ = io.WriteString(w, "data: first\n\n")
				w.(http.Flusher).Flush()
				time.Sleep(110 * time.Millisecond) // Longer than the normal request budget.
				_, _ = io.WriteString(w, "data: second\n\n")
				w.(http.Flusher).Flush()
			}))
			engine.upstreams["u"].config.RequestTimeoutMS = 50
			engine.upstreams["u"].config.StreamIdleMS = 350
			server := httptest.NewUnstartedServer(engine)
			server.EnableHTTP2 = h2
			if h2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			client := server.Client()
			client.Timeout = 3 * time.Second
			resp, err := client.Get(server.URL + "/events")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if (resp.ProtoMajor == 2) != h2 {
				t.Fatalf("unexpected downstream protocol %s", resp.Proto)
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil || string(got) != "data: first\n\ndata: second\n\n" {
				t.Fatalf("stream=%q err=%v", got, err)
			}
		})
	}
}

func TestSSEIdleTimeoutCancelsBackend(t *testing.T) {
	ended := make(chan struct{})
	engine, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(ended)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	engine.upstreams["u"].config.StreamIdleMS = 60
	server := httptest.NewServer(engine)
	defer server.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stream did not honor idle timeout: %v", err)
	}
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("idle stream did not cancel upstream")
	}
}

func TestOrdinaryRequestStillHasTotalTimeout(t *testing.T) {
	engine, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	engine.upstreams["u"].config.RequestTimeoutMS = 50
	server := httptest.NewServer(engine)
	defer server.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502 after deadline", resp.StatusCode)
	}
}

func TestWebSocketDebugLongLivedAndIdleTimeout(t *testing.T) {
	engine, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			kind, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if err := conn.Write(r.Context(), kind, data); err != nil {
				return
			}
		}
	}))
	engine.config.Debug = true
	engine.upstreams["u"].config.RequestTimeoutMS = 45
	engine.upstreams["u"].config.StreamIdleMS = 260
	server := httptest.NewServer(engine)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	for i := range 2 {
		if i == 1 {
			time.Sleep(100 * time.Millisecond) // Exceeds request timeout, not idle timeout.
		}
		data := bytes.Repeat([]byte{byte('a' + i)}, 32<<10)
		if err := conn.Write(ctx, websocket.MessageBinary, data); err != nil {
			t.Fatal(err)
		}
		_, got, err := conn.Read(ctx)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("echo %d: n=%d err=%v", i, len(got), err)
		}
	}
	_, _, err = conn.Read(ctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("idle upgraded connection not terminated: %v", err)
	}
}

func TestWebSocketClientTrafficResetsIdleTimeout(t *testing.T) {
	engine, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			kind, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if string(data) == "echo" {
				_ = conn.Write(r.Context(), kind, data)
			}
		}
	}))
	engine.upstreams["u"].config.StreamIdleMS = 180
	server := httptest.NewServer(engine)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	for range 6 {
		if err := conn.Write(ctx, websocket.MessageText, []byte("keep")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(55 * time.Millisecond)
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte("echo")); err != nil {
		t.Fatal(err)
	}
	_, response, err := conn.Read(ctx)
	if err != nil || string(response) != "echo" {
		t.Fatalf("client traffic did not keep upgraded connection active: data=%q err=%v", response, err)
	}
}

func TestHTTP2GRPCBidirectionalStreamsSurviveRequestTimeout(t *testing.T) {
	frame := []byte{0, 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("backend protocol=%s", r.Proto)
			return
		}
		w.Header().Set("Content-Type", "application/grpc+proto")
		flusher := w.(http.Flusher)
		for range 2 {
			got := make([]byte, len(frame))
			if _, err := io.ReadFull(r.Body, got); err != nil {
				return
			}
			_, _ = w.Write(got)
			flusher.Flush()
		}
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	proxy := &mockOutbound{destination: strings.TrimPrefix(upstream.URL, "https://")}
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	engine, err := NewEngine(
		contract.Gateway{Default: contract.Action{Type: "reverse_proxy", Upstream: "u"}},
		nil,
		[]contract.Upstream{{ID: "u", Backends: []contract.Backend{{URL: upstream.URL}}, TrustPEM: string(trust), RequestTimeoutMS: 150, StreamIdleMS: 400}},
		func(_ context.Context, dst netapi.Address, _ route.Target) (Selection, error) {
			return Selection{Identity: "grpc-bidi", Proxy: proxy, Destination: dst}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	server := httptest.NewUnstartedServer(engine)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/bidi", reader)
	request.Header.Set("Content-Type", "application/grpc+proto")
	written := make(chan error, 1)
	go func() {
		if _, err := writer.Write(frame); err != nil {
			written <- err
			return
		}
		time.Sleep(220 * time.Millisecond) // Long after the initial request budget.
		_, err := writer.Write(frame)
		_ = writer.CloseWithError(err)
		written <- err
	}()
	resp, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("downstream protocol=%s", resp.Proto)
	}
	out := make([]byte, 2*len(frame))
	if _, err := io.ReadFull(resp.Body, out); err != nil || !bytes.Equal(out, append(bytes.Clone(frame), frame...)) {
		t.Fatalf("bidi grpc=%v err=%v", out, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestHotUpdatePreservesAdmittedWebSocket(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			kind, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if err := conn.Write(r.Context(), kind, data); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	proxy := &mockOutbound{destination: strings.TrimPrefix(upstream.URL, "http://")}
	cfg := contract.Config{
		Gateways: []contract.Gateway{{ID: "g", Name: "gateway", Enabled: true, Listen: "127.0.0.1:0", Default: contract.Action{Type: "reverse_proxy", Upstream: "u"}}},
		Upstreams: []contract.Upstream{{ID: "u", Backends: []contract.Backend{{URL: upstream.URL}}}},
	}
	manager, _ := newTestManager(t, cfg, func(_ context.Context, dst netapi.Address, _ route.Target) (Selection, error) {
		return Selection{Identity: "up", Proxy: proxy, Destination: dst}, nil
	})
	address := manager.listeners["127.0.0.1:0"].raw.Addr().String()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws://"+address+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	exchange := func(message string) {
		t.Helper()
		if err := conn.Write(ctx, websocket.MessageText, []byte(message)); err != nil {
			t.Fatal(err)
		}
		_, got, err := conn.Read(ctx)
		if err != nil || string(got) != message {
			t.Fatalf("after hot update: echo=%q err=%v", got, err)
		}
	}
	exchange("before")
	draft := manager.Config()
	draft.Gateways[0].Debug = true
	if _, err := manager.Save(t.Context(), draft); err != nil {
		t.Fatal(err)
	}
	exchange("after") // Unchanged listener ownership must retain active upgrades.
}

func TestStreamIdleConfigValidation(t *testing.T) {
	_, err := compileUpstream(contract.Upstream{ID: "u", Backends: []contract.Backend{{URL: "http://127.0.0.1:9000"}}, StreamIdleMS: -1})
	if err == nil {
		t.Fatal("accepted negative stream idle timeout")
	}
}

func TestActiveSSESurvivesTransportPoolRetirement(t *testing.T) {
	engine, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(95 * time.Millisecond)
		_, _ = io.WriteString(w, "data: second\n\n")
		w.(http.Flusher).Flush()
	}))
	server := httptest.NewServer(engine)
	defer server.Close()
	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	if err := engine.pool.Close(); err != nil {
		t.Fatal(err)
	}
	last := make([]byte, len("data: second\n\n"))
	if _, err := io.ReadFull(resp.Body, last); err != nil || string(last) != "data: second\n\n" {
		t.Fatalf("active stream ended on idle pool retirement: %q %v", last, err)
	}
}

// Ensure h2 stream request/cancellation never accidentally closes another stream.
func TestHTTP2SSEIndependentCancellation(t *testing.T) {
	engine, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: live\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	server := httptest.NewUnstartedServer(engine)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	ctx, cancel := context.WithCancel(t.Context())
	firstRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	first, err := client.Do(firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	second, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	cancel()
	_ = first.Body.Close()
	buf := make([]byte, len("data: live\n\n"))
	if _, err := io.ReadFull(second.Body, buf); err != nil || string(buf) != "data: live\n\n" {
		t.Fatalf("one cancelled h2 stream interrupted another: %q %v", buf, err)
	}
}

