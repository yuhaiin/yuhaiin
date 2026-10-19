package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func BenchmarkPathRuleMatching(b *testing.B) {
	rules := make([]contract.Rule, 100)
	for n := range rules {
		rules[n] = contract.Rule{ID: fmt.Sprint(n), Enabled: true, Priority: n, Match: contract.Condition{Field: "path", Operator: "prefix", Value: fmt.Sprintf("/route/%d/", n)}, Action: contract.Action{Type: "block", Status: 204}}
	}
	p, err := CompilePolicy(rules, contract.Action{Type: "forward"})
	if err != nil {
		b.Fatal(err)
	}
	request := httptest.NewRequest("GET", "http://example.com/route/99/asset", nil)
	ctx := netapi.WithContext(b.Context())
	b.ReportAllocs()
	for b.Loop() {
		if p.evaluate(request, ctx, false).RuleID != "99" {
			b.Fatal("incorrect rule")
		}
	}
}

func BenchmarkReverseProxy(b *testing.B) {
	for _, h2 := range []bool{false, true} {
		name := "HTTP1"
		if h2 {
			name = "HTTP2"
		}
		b.Run(name, func(b *testing.B) {
			payload := make([]byte, 16<<10)
			engine, _ := testEngine(b, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) }))
			server := httptest.NewUnstartedServer(engine)
			server.EnableHTTP2 = h2
			if h2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			client := server.Client()
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				response, err := client.Get(server.URL + "/data")
				if err != nil {
					b.Fatal(err)
				}
				_, err = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCertificateHandshake(b *testing.B) {
	ca, err := cert.GenerateCa()
	if err != nil {
		b.Fatal(err)
	}
	root, _ := ca.CertBytes()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	for _, cached := range []bool{false, true} {
		name := "IssueEachHandshake"
		if cached {
			name = "CachedLeaf"
		}
		b.Run(name, func(b *testing.B) {
			cache := cert.NewCache(ca, 512)
			_, err := cache.Get(x509.ECDSA, "example.com")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				left, right := net.Pipe()
				config := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					if cached {
						return cache.Get(x509.ECDSA, "example.com")
					}
					leaf, err := ca.GenerateServerCertWithAlgorithm(x509.ECDSA, "example.com")
					if err != nil {
						return nil, err
					}
					tc, err := leaf.TlsCert()
					return &tc, err
				}}
				done := make(chan error, 1)
				go func() { done <- tls.Server(left, config).HandshakeContext(b.Context()) }()
				err := tls.Client(right, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "example.com"}).HandshakeContext(b.Context())
				_ = right.Close()
				_ = left.Close()
				serverErr := <-done
				if err != nil || serverErr != nil {
					b.Fatalf("client=%v server=%v", err, serverErr)
				}
			}
		})
	}
}

func BenchmarkDisabledInterception(b *testing.B) {
	m, _ := newTestManager(b, contract.Config{}, nil)
	ctx := netapi.WithContext(b.Context())
	meta := new(netapi.StreamMeta)
	b.ReportAllocs()
	for b.Loop() {
		if m.InterceptGateway(ctx, meta, "g") {
			b.Fatal("disabled interception accepted stream")
		}
	}
}

func BenchmarkConcurrentReverseProxy(b *testing.B) {
	payload := make([]byte, 16<<10)
	engine, _ := testEngine(b, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) }))
	server := httptest.NewUnstartedServer(engine)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	var mu sync.Mutex
	latencies := make([]int64, 0, 8192)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			start := time.Now()
			response, err := client.Get(server.URL)
			if err != nil {
				b.Error(err)
				continue
			}
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			elapsed := time.Since(start).Nanoseconds()
			if err != nil {
				b.Error(err)
			}
			mu.Lock()
			if len(latencies) < cap(latencies) {
				latencies = append(latencies, elapsed)
			}
			mu.Unlock()
		}
	})
	slices.Sort(latencies)
	if len(latencies) > 0 {
		b.ReportMetric(float64(latencies[len(latencies)/2])/1000, "p50-us")
		b.ReportMetric(float64(latencies[len(latencies)*95/100])/1000, "p95-us")
	}
}

// This isolates request context + effective-outbound callback + warm pool lookup.
// Synthetic A/B callbacks exclude actual Route matching, DNS and socket traffic;
// complete HTTP request benchmarks above include the engine's forwarding work.
func BenchmarkRequestOutboundSelectionAndPool(b *testing.B) {
	address, _ := netapi.ParseAddress("tcp", "example.com:443")
	proxies := map[string]*mockOutbound{"a": {}, "b": {}}
	selectOutbound := func(_ context.Context, a netapi.Address, target route.Target) (Selection, error) {
		return Selection{Proxy: proxies[target.ID], Identity: target.ID, Destination: a}, nil
	}
	transports := NewTransportPool(256)
	defer transports.Close()
	ctx := netapi.WithContext(b.Context())
	n := 0
	b.ReportAllocs()
	for b.Loop() {
		id := "a"
		if n%2 == 1 {
			id = "b"
		}
		n++
		selection, err := selectOutbound(netapi.ForkContext(ctx), address, route.Target{Type: "node", ID: id})
		if err != nil {
			b.Fatal(err)
		}
		_, release, err := transports.borrow(selection, "https://example.com", contract.Upstream{})
		if err != nil {
			b.Fatal(err)
		}
		release()
	}
}
