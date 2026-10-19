package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type mockOutbound struct {
	netapi.Proxy
	destination string
	dials       atomic.Int64
}

func (p *mockOutbound) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	p.dials.Add(1)
	return new(net.Dialer).DialContext(ctx, "tcp", p.destination)
}

func testEngine(t testing.TB, rules []contract.Rule, handler http.Handler) (*Engine, *mockOutbound) {
	t.Helper()
	up := httptest.NewServer(handler)
	t.Cleanup(up.Close)
	p := &mockOutbound{destination: strings.TrimPrefix(up.URL, "http://")}
	e, err := NewEngine(contract.Gateway{ID: "g", Name: "gateway", Enabled: true, Default: contract.Action{Type: "reverse_proxy", Upstream: "u"}}, rules, []contract.Upstream{{ID: "u", Backends: []contract.Backend{{URL: "http://upstream.invalid"}}}}, func(_ context.Context, a netapi.Address, _ route.Target) (Selection, error) {
		return Selection{Identity: "mock", Proxy: p, Destination: a}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e, p
}

func TestPolicyActionsAndMatching(t *testing.T) {
	rules := []contract.Rule{
		{ID: "compound", Enabled: true, Priority: 1, Match: contract.Condition{All: []contract.Condition{{Field: "host", Operator: "domain", Value: "example.com"}, {Field: "path", Operator: "regex", Value: "^/ads/[a-z]+$"}, {Field: "method", Value: "GET"}, {Field: "query", Key: "tracking", Value: "yes"}, {Field: "header", Key: "X-Test", Value: "true"}, {Not: &contract.Condition{Field: "path", Value: "/ads/allowed"}}}}, Action: contract.Action{Type: "block", Status: 204}},
		{ID: "redirect", Enabled: true, Priority: 2, Match: contract.Condition{Field: "path", Value: "/old"}, Action: contract.Action{Type: "redirect", Status: 307, Location: "/new"}},
		{ID: "respond", Enabled: true, Priority: 3, Match: contract.Condition{Any: []contract.Condition{{Field: "path", Value: "/respond"}, {Field: "path", Value: "/json"}}}, Action: contract.Action{Type: "respond", Body: `{"ok":true}`, ResponseHeaders: http.Header{"Content-Type": {"application/json"}}}},
	}
	e, _ := testEngine(t, rules, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "upstream") }))
	for _, tc := range []struct {
		url  string
		code int
		body string
	}{{"http://sub.example.com/ads/banner?tracking=yes", 204, ""}, {"http://example.com/ads/allowed?tracking=yes", 200, "upstream"}, {"http://badexample.com/ads/banner?tracking=yes", 200, "upstream"}, {"http://example.com/old", 307, ""}, {"http://example.com/json", 200, `{"ok":true}`}} {
		t.Run(tc.url, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.url, nil)
			r.Header.Set("X-Test", "true")
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			if w.Code != tc.code {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			if tc.body != "" && w.Body.String() != tc.body {
				t.Fatalf("body=%s", w.Body)
			}
		})
	}
	result, err := e.Test(contract.TestRequest{URL: "https://example.com/json", Method: "GET"})
	if err != nil || result.RuleID != "respond" || !result.RequiresMITM || len(result.Steps) != 3 {
		t.Fatalf("test=%+v err=%v", result, err)
	}
}

func TestPolicySnapshotOwnsDraftAndValidates(t *testing.T) {
	rules := []contract.Rule{{ID: "r", Enabled: true, Match: contract.Condition{Field: "path", Value: "/x"}, Action: contract.Action{Type: "respond", Body: "first"}}}
	p, err := CompilePolicy(rules, contract.Action{Type: "block"})
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Action.Body = "mutated"
	rules[0].Match.Value = "/other"
	if got := p.evaluate(httptest.NewRequest("GET", "http://host/x", nil), netapi.WithContext(t.Context()), true); got.Action.Body != "first" {
		t.Fatalf("snapshot mutated: %+v", got)
	}
	for _, action := range []contract.Action{{Type: "unknown"}, {Type: "redirect", Status: 200, Location: "/"}, {Type: "forward", Rewrite: contract.Rewrite{Headers: http.Header{"X-Test": {"a\r\nb"}}}}, {Type: "forward", Rewrite: contract.Rewrite{Scheme: "file"}}, {Type: "forward", Outbound: route.Target{Type: "node"}}} {
		if _, err := CompilePolicy(nil, action); err == nil {
			t.Fatalf("accepted invalid action %+v", action)
		}
	}
}

func TestHTTP2RequestOutboundIsolationAndSelectorChange(t *testing.T) {
	makeBackend := func(body string) *mockOutbound {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		t.Cleanup(server.Close)
		return &mockOutbound{destination: strings.TrimPrefix(server.URL, "http://")}
	}
	a, b := makeBackend("A"), makeBackend("B")
	var selected atomic.Pointer[mockOutbound]
	selected.Store(a)
	rules := []contract.Rule{{ID: "download", Enabled: true, Match: contract.Condition{Field: "path", Operator: "prefix", Value: "/download/"}, Action: contract.Action{Type: "reverse_proxy", Upstream: "u", Outbound: route.Target{Type: "node", ID: "b"}}}}
	e, err := NewEngine(contract.Gateway{ID: "g", Default: contract.Action{Type: "reverse_proxy", Upstream: "u", Outbound: route.Target{Type: "selector", ID: "s"}}}, rules, []contract.Upstream{{ID: "u", Backends: []contract.Backend{{URL: "http://same-origin.invalid"}}}}, func(_ context.Context, dst netapi.Address, target route.Target) (Selection, error) {
		p := selected.Load()
		if target.ID == "b" {
			p = b
		}
		return Selection{Identity: fmt.Sprintf("%p", p), Proxy: p, Destination: dst}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	server := httptest.NewUnstartedServer(e)
	server.EnableHTTP2 = true
	var accepted atomic.Int64
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	get := func(path, want string) {
		t.Helper()
		response, err := client.Get(server.URL + path)
		if err != nil {
			t.Error(err)
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != want || response.ProtoMajor != 2 {
			t.Errorf("path=%s body=%s proto=%s err=%v", path, body, response.Proto, err)
		}
	}
	get("/api/first", "A")
	get("/download/first", "B")
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() { get("/api/concurrent", "A") })
		wg.Go(func() { get("/download/concurrent", "B") })
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("downstream connections=%d, expected one H2 connection", accepted.Load())
	}
	beforeA := a.dials.Load()
	if beforeA >= 13 {
		t.Fatalf("A connections were not reused: %d", beforeA)
	}
	selected.Store(b)
	get("/api/after-selector-update", "B")
	if a.dials.Load() != beforeA {
		t.Fatal("selector update dialed old A")
	}
}

func TestRewriteHostForwardingAndTLSVerification(t *testing.T) {
	rules := []contract.Rule{{ID: "rewrite", Enabled: true, Match: contract.Condition{}, Action: contract.Action{Type: "reverse_proxy", Upstream: "u", PreserveHost: true, Rewrite: contract.Rewrite{Path: "/rewritten", Query: new("a=b"), Headers: http.Header{"X-Added": {"yes"}}}, ResponseHeaders: http.Header{"X-Response": {"yes"}}}}}
	e, _ := testEngine(t, rules, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "app.example" || r.URL.RequestURI() != "/rewritten?a=b" || r.Header.Get("X-Added") != "yes" || r.Header.Get("X-Forwarded-Host") != "app.example" || strings.Contains(r.Header.Get("X-Forwarded-For"), "untrusted") {
			t.Errorf("unexpected request host=%s url=%s headers=%v", r.Host, r.URL, r.Header)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	r := httptest.NewRequest("GET", "http://app.example/original", nil)
	r.Header.Set("X-Forwarded-For", "untrusted")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("X-Response") != "yes" {
		t.Fatalf("response=%+v", w)
	}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer up.Close()
	p := &mockOutbound{destination: strings.TrimPrefix(up.URL, "https://")}
	secure, err := NewEngine(contract.Gateway{Default: contract.Action{Type: "reverse_proxy", Upstream: "tls"}}, nil, []contract.Upstream{{ID: "tls", Backends: []contract.Backend{{URL: up.URL}}}}, func(_ context.Context, dst netapi.Address, _ route.Target) (Selection, error) {
		return Selection{Identity: "tls", Proxy: p, Destination: dst}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Close()
	w = httptest.NewRecorder()
	secure.ServeHTTP(w, httptest.NewRequest("GET", "http://app.example/", nil))
	if w.Code != 502 {
		t.Fatalf("untrusted upstream status=%d", w.Code)
	}
}

func TestStreamingAndCancellation(t *testing.T) {
	observedCancel := make(chan struct{})
	e, _ := testEngine(t, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(observedCancel)
	}))
	server := httptest.NewServer(e)
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = resp.Body.Close()
	select {
	case <-observedCancel:
	case <-time.After(2 * time.Second):
		t.Fatal("request cancellation did not reach backend")
	}
}

func TestForwardRequiresOriginalDestination(t *testing.T) {
	e, err := NewEngine(contract.Gateway{Default: contract.Action{Type: "forward"}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest("GET", "http://internal.example/", nil))
	if w.Code != 502 {
		t.Fatalf("open forward status=%d", w.Code)
	}
}
