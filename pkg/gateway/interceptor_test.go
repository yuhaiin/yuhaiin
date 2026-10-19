package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

type memoryStore struct {
	mu         sync.Mutex
	config     contract.Config
	root, key  []byte
	caRevision uint64
	failSave   bool
}

func (s *memoryStore) Load(context.Context) (contract.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config, nil
}
func (s *memoryStore) Save(_ context.Context, c contract.Config) (contract.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSave {
		return c, errors.New("disk unavailable")
	}
	if c.Revision != s.config.Revision {
		return c, store.ErrConflict
	}
	c.Revision++
	s.config = c
	return c, nil
}
func (s *memoryStore) LoadCA(context.Context) ([]byte, []byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.root), bytes.Clone(s.key), s.caRevision, nil
}
func (s *memoryStore) SaveCA(_ context.Context, root, key []byte, revision uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.caRevision {
		return revision, store.ErrConflict
	}
	s.caRevision++
	s.root = bytes.Clone(root)
	s.key = bytes.Clone(key)
	return s.caRevision, nil
}

func newTestManager(t testing.TB, config contract.Config, selectOutbound SelectOutbound) (*Manager, *memoryStore) {
	t.Helper()
	storage := &memoryStore{}
	authority, err := NewAuthority(t.Context(), storage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Generate(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(t.Context(), storage, authority, selectOutbound)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if _, err := m.Save(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	return m, storage
}

func interceptListener(t *testing.T, m *Manager, destination, fallback string) (string, *sync.WaitGroup) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var workers sync.WaitGroup
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				ctx := netapi.WithContext(t.Context()).SetInboundID("in")
				ctx.Source = c.RemoteAddr()
				dst, _ := netapi.ParseAddress("tcp", destination)
				ctx.Destination = dst
				meta := &netapi.StreamMeta{Src: c, Address: dst, Source: c.RemoteAddr(), Destination: dst, InboundID: "in"}
				if m.InterceptGateway(ctx, meta, "g") {
					return
				}
				defer meta.Src.Close()
				remote, err := new(net.Dialer).DialContext(t.Context(), "tcp", fallback)
				if err != nil {
					return
				}
				defer remote.Close()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(remote, meta.Src); _ = remote.Close(); close(done) }()
				_, _ = io.Copy(meta.Src, remote)
				_ = meta.Src.Close()
				<-done
			})
		}
	}()
	return listener.Addr().String(), &workers
}

func TestHTTPSMITMHTTP2AndPassthrough(t *testing.T) {
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "backend:"+r.URL.Path) }))
	up.EnableHTTP2 = true
	up.StartTLS()
	defer up.Close()
	backendPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw})
	p := &mockOutbound{destination: strings.TrimPrefix(up.URL, "https://")}
	for _, tc := range []struct {
		name, mode string
		exclude    []string
		trustMITM  bool
		wantError  bool
	}{{"MITM trusted", "https_mitm", nil, true, false}, {"untrusted MITM", "https_mitm", nil, false, true}, {"TLS passthrough", "tls_passthrough", nil, false, false}, {"excluded domain", "https_mitm", []string{"example.com"}, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "reverse_proxy", Upstream: "u"}}}, Upstreams: []contract.Upstream{{ID: "u", TrustPEM: string(backendPEM), Backends: []contract.Backend{{URL: up.URL}}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: tc.mode, Domains: []string{"example.com"}, ExcludeDomains: tc.exclude}}}
			m, _ := newTestManager(t, config, func(_ context.Context, dst netapi.Address, _ route.Target) (Selection, error) {
				return Selection{Identity: "up", Proxy: p, Destination: dst}, nil
			})
			address, _ := interceptListener(t, m, "example.com:443", p.destination)
			roots := x509.NewCertPool()
			if tc.trustMITM {
				roots.AppendCertsFromPEM([]byte(m.CAStatus().CertificatePEM))
			} else {
				roots.AppendCertsFromPEM(backendPEM)
			}
			tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, "tcp", address)
			}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			resp, err := client.Get("https://example.com/test")
			if tc.wantError {
				if err == nil {
					_ = resp.Body.Close()
					t.Fatal("untrusted MITM succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "backend:/test" || resp.ProtoMajor != 2 {
				t.Fatalf("body=%s proto=%s", body, resp.Proto)
			}
			if tc.trustMITM && m.CAStatus().CachedCertificates != 1 {
				t.Fatal("MITM certificate was not cached")
			}
		})
	}
}

func TestPlaintextInterceptionAndProbeReplay(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) }))
	defer up.Close()
	p := &mockOutbound{destination: strings.TrimPrefix(up.URL, "http://")}
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, RuleIDs: []string{"ads"}, Default: contract.Action{Type: "forward"}}}, Rules: []contract.Rule{{ID: "ads", Enabled: true, Match: contract.Condition{Field: "path", Operator: "prefix", Value: "/ads/"}, Action: contract.Action{Type: "block", Status: 204}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "http_only", Domains: []string{"example.com"}}}}
	m, _ := newTestManager(t, config, func(_ context.Context, dst netapi.Address, _ route.Target) (Selection, error) {
		return Selection{Identity: "up", Proxy: p, Destination: dst}, nil
	})
	address, _ := interceptListener(t, m, "example.com:80", p.destination)
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, "tcp", address)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	for _, path := range []string{"/echo", "/ads/banner"} {
		resp, err := client.Post("http://example.com"+path, "text/plain", strings.NewReader("streamed payload"))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if path == "/echo" && string(body) != "streamed payload" {
			t.Fatalf("body=%s", body)
		}
		if path != "/echo" && resp.StatusCode != 204 {
			t.Fatal(resp.Status)
		}
	}
	// A non-HTTP binary prefix is left byte-for-byte available to the caller.
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	dst, _ := netapi.ParseAddress("tcp", "example.com:80")
	ctx := netapi.WithContext(t.Context()).SetInboundID("in")
	meta := &netapi.StreamMeta{Src: left, Address: dst}
	go func() { _, _ = right.Write([]byte{0, 1, 2, 3}) }()
	if m.InterceptGateway(ctx, meta, "g") {
		t.Fatal("binary stream intercepted")
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(meta.Src, buf); err != nil || !bytes.Equal(buf, []byte{0, 1, 2, 3}) {
		t.Fatalf("probe lost bytes: %v %v", buf, err)
	}
}

func TestSnapshotRollbackAndConcurrentRequests(t *testing.T) {
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "respond", Body: "old"}}}}
	m, storage := newTestManager(t, config, nil)
	draft := m.Config()
	draft.Gateways[0].Default.Body = "new"
	storage.mu.Lock()
	storage.failSave = true
	storage.mu.Unlock()
	if _, err := m.Save(t.Context(), draft); err == nil {
		t.Fatal("failed persistence accepted")
	}
	if m.Config().Gateways[0].Default.Body != "old" {
		t.Fatal("failed save changed running configuration")
	}
	storage.mu.Lock()
	storage.failSave = false
	storage.mu.Unlock()
	var workers sync.WaitGroup
	for range 10 {
		workers.Go(func() {
			for range 20 {
				if _, err := m.Test(contract.TestRequest{GatewayID: "g", URL: "http://example.com/"}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	for range 10 {
		draft = m.Config()
		draft.Gateways[0].Default.Body = "updated"
		if _, err := m.Save(t.Context(), draft); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
	if _, err := m.Save(t.Context(), config); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale save err=%v", err)
	}
}

func TestGatewayRejectsOutboundReentryThroughListener(t *testing.T) {
	p := new(mockOutbound)
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "Loop test", Enabled: true, Listen: "127.0.0.1:0", Default: contract.Action{Type: "reverse_proxy", Upstream: "loop"}}}, Upstreams: []contract.Upstream{{ID: "loop", Backends: []contract.Backend{{URL: "http://alias.invalid"}}}}}
	m, _ := newTestManager(t, config, func(_ context.Context, dst netapi.Address, _ route.Target) (Selection, error) {
		return Selection{Identity: "loop", Proxy: p, Destination: dst}, nil
	})
	p.destination = m.listeners["127.0.0.1:0"].raw.Addr().String()
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + p.destination + "/loop")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusLoopDetected || p.dials.Load() != 1 {
		t.Fatalf("status=%d recursive dials=%d", response.StatusCode, p.dials.Load())
	}
}
