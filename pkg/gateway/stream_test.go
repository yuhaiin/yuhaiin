package gateway

import (
	"bytes"
	"context"
	"encoding/pem"
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

func TestWebSocketUpgradeIsBidirectional(t *testing.T) {
	engine, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		kind, data, err := conn.Read(r.Context())
		if err == nil {
			_ = conn.Write(r.Context(), kind, data)
		}
	}))
	server := httptest.NewServer(engine)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	if err := conn.Write(ctx, websocket.MessageText, []byte("streaming websocket")); err != nil {
		t.Fatal(err)
	}
	_, data, err := conn.Read(ctx)
	if err != nil || string(data) != "streaming websocket" {
		t.Fatalf("data=%s err=%v", data, err)
	}
}

func TestGRPCFramesAndTrailersOverHTTP2Upstream(t *testing.T) {
	frame := []byte{0, 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream protocol=%s", r.Proto)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, frame) {
			t.Errorf("request frame=%v err=%v", body, err)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(frame)
		w.Header().Set("Grpc-Status", "0")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	p := &mockOutbound{destination: strings.TrimPrefix(upstream.URL, "https://")}
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	engine, err := NewEngine(contract.Gateway{Default: contract.Action{Type: "reverse_proxy", Upstream: "u"}}, nil, []contract.Upstream{{ID: "u", TrustPEM: string(trust), Backends: []contract.Backend{{URL: upstream.URL}}}}, func(_ context.Context, a netapi.Address, _ route.Target) (Selection, error) {
		return Selection{Identity: "grpc", Proxy: p, Destination: a}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	downstream := httptest.NewUnstartedServer(engine)
	downstream.EnableHTTP2 = true
	downstream.StartTLS()
	defer downstream.Close()
	request, _ := http.NewRequestWithContext(t.Context(), "POST", downstream.URL+"/test.Service/Method", bytes.NewReader(frame))
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("Te", "trailers")
	response, err := downstream.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(data, frame) || response.Trailer.Get("Grpc-Status") != "0" || response.ProtoMajor != 2 {
		t.Fatalf("frame=%v trailers=%v protocol=%s err=%v", data, response.Trailer, response.Proto, err)
	}
}

func TestLargeResponseStreamsWithBoundedBuffer(t *testing.T) {
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	engine, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 128 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	server := httptest.NewServer(engine)
	defer server.Close()
	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	n, err := io.Copy(io.Discard, response.Body)
	if err != nil || n != 8<<20 {
		t.Fatalf("streamed bytes=%d err=%v", n, err)
	}
}
