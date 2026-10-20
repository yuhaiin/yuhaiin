package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

func BenchmarkSSEProxyFrames(b *testing.B) {
	for _, h2 := range []bool{false, true} {
		name := "HTTP1"
		if h2 {
			name = "HTTP2"
		}
		b.Run(name, func(b *testing.B) {
			engine, _ := testEngine(b, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				for range 4 {
					_, _ = io.WriteString(w, "data: 1234567890\n\n")
					w.(http.Flusher).Flush()
				}
			}))
			server := httptest.NewUnstartedServer(engine)
			server.EnableHTTP2 = h2
			if h2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			client := server.Client()
			b.ReportAllocs()
			for b.Loop() {
				resp, err := client.Get(server.URL + "/events")
				if err != nil {
					b.Fatal(err)
				}
				_, err = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkWebSocketProxyEcho(b *testing.B) {
	engine, _ := testEngine(b, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
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
	server := httptest.NewServer(engine)
	defer server.Close()
	conn, _, err := websocket.Dial(b.Context(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	payload := []byte("websocket stream benchmark payload")
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if err := conn.Write(b.Context(), websocket.MessageBinary, payload); err != nil {
			b.Fatal(err)
		}
		_, msg, err := conn.Read(b.Context())
		if err != nil || string(msg) != string(payload) {
			b.Fatalf("echo=%q err=%v", msg, err)
		}
	}
}
