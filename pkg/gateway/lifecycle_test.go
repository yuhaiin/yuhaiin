package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
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

func TestWildcardListenerOnlyRejectsLocalDestinations(t *testing.T) {
	for _, listener := range []string{"0.0.0.0:443", "[::]:443", ":443"} {
		t.Run(listener, func(t *testing.T) {
			m := &Manager{selectOutbound: func(_ context.Context, a netapi.Address, _ route.Target) (Selection, error) {
				return Selection{Proxy: new(mockOutbound), Destination: a}, nil
			}}
			m.current.Store(&snapshot{listeners: map[string]*gatewayRuntime{listener: {}}})
			for _, host := range []string{"remote.example", "203.0.113.10", "2001:db8::10", "127.0.0.1", "::1", "localhost"} {
				a, err := netapi.ParseAddress("tcp", net.JoinHostPort(host, "443"))
				if err != nil {
					t.Fatal(err)
				}
				_, err = m.selectForRequest(t.Context(), a, route.Target{})
				local := host == "localhost" || host == "127.0.0.1" || host == "::1"
				if (err != nil) != local {
					t.Errorf("host=%s err=%v", host, err)
				}
			}
		})
	}
}

func TestMITMHotAdmissionRevokesHTTP2Session(t *testing.T) {
	for _, change := range []string{"exclude", "domains", "ports", "sources", "processes", "mode", "disable"} {
		t.Run(change, func(t *testing.T) {
			config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "respond", Body: "ok"}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "https_mitm", Domains: []string{"example.com"}}}}
			m, _ := newTestManager(t, config, nil)
			address, workers := interceptListener(t, m, "example.com:443", "127.0.0.1:1")
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM([]byte(m.CAStatus().CertificatePEM))
			transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, "tcp", address)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			response, err := client.Get("https://example.com/")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.ProtoMajor != 2 {
				t.Fatal(response.Proto)
			}
			draft := m.Config()
			i := &draft.Interceptions[0]
			switch change {
			case "exclude":
				i.ExcludeDomains = []string{"example.com"}
			case "domains":
				i.Domains = []string{"other.example"}
			case "ports":
				i.Ports = []uint16{8443}
			case "sources":
				i.Sources = []string{"192.0.2.0/24"}
			case "processes":
				i.Processes = []string{"other-process"}
			case "mode":
				i.Mode = "off"
			case "disable":
				draft.Gateways[0].Enabled = false
			}
			if _, err := m.Save(t.Context(), draft); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { workers.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("revoked HTTP/2 session is still alive")
			}
		})
	}
}

func TestManagedListenerClosesHijackedConnections(t *testing.T) {
	for _, change := range []string{"disable", "delete", "shutdown", "replace"} {
		t.Run(change, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer func() { _ = c.CloseNow() }()
				for {
					kind, data, err := c.Read(r.Context())
					if err != nil {
						return
					}
					if err = c.Write(r.Context(), kind, data); err != nil {
						return
					}
				}
			}))
			defer upstream.Close()
			p := &mockOutbound{destination: strings.TrimPrefix(upstream.URL, "http://")}
			config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Listen: "127.0.0.1:0", Default: contract.Action{Type: "reverse_proxy", Upstream: "u"}}}, Upstreams: []contract.Upstream{{ID: "u", Backends: []contract.Backend{{URL: upstream.URL}}}}}
			m, _ := newTestManager(t, config, func(_ context.Context, a netapi.Address, _ route.Target) (Selection, error) {
				return Selection{Identity: "up", Proxy: p, Destination: a}, nil
			})
			address := m.listeners["127.0.0.1:0"].raw.Addr().String()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			conn, _, err := websocket.Dial(ctx, "ws://"+address+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.CloseNow() }()
			if err := conn.Write(ctx, websocket.MessageText, []byte("echo")); err != nil {
				t.Fatal(err)
			}
			if _, _, err := conn.Read(ctx); err != nil {
				t.Fatal(err)
			}
			if change == "shutdown" {
				_ = m.Close()
			} else {
				draft := m.Config()
				switch change {
				case "replace":
					draft.Gateways[0].ID = "new-owner"
					draft.Gateways[0].Revision = 0
				case "delete":
					draft.Gateways = nil
				default:
					draft.Gateways[0].Enabled = false
				}
				if _, err := m.Save(t.Context(), draft); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err = conn.Read(ctx)
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("upgraded connection was not closed: %v", err)
			}
		})
	}
}

func TestRuleTesterEffectiveOutboundAndTLSOwnership(t *testing.T) {
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "reverse_proxy", Upstream: "u"}}}, Upstreams: []contract.Upstream{{ID: "u", Outbound: route.Target{Type: "direct"}, Backends: []contract.Backend{{URL: "https://example.com"}}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "https_mitm", Domains: []string{"example.com"}, ExcludeDomains: []string{"excluded.example.com"}}}}
	m, _ := newTestManager(t, config, nil)
	for _, tc := range []struct {
		url, inbound string
		mitm         bool
	}{{"https://example.com/", "", true}, {"https://example.com/", "other", true}, {"https://example.com/", "in", true}, {"https://excluded.example.com/", "in", false}, {"https://other.example/", "in", false}, {"http://example.com/", "in", false}} {
		result, err := m.Test(contract.TestRequest{GatewayID: "g", URL: tc.url, InboundID: tc.inbound})
		if err != nil || result.RequiresMITM != tc.mitm || result.Action.Outbound.Type != "direct" {
			t.Fatalf("%+v result=%+v err=%v", tc, result, err)
		}
	}
}

func TestRuleTesterAdmissionSourceIP(t *testing.T) {
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "block"}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "https_mitm", Domains: []string{"example.com"}, Sources: []string{"192.0.2.0/24"}}}}
	m, _ := newTestManager(t, config, nil)
	for _, tc := range []struct {
		source string
		mitm   bool
	}{{"192.0.2.1", true}, {"198.51.100.1", false}, {"", false}} {
		result, err := m.Test(contract.TestRequest{GatewayID: "g", URL: "https://example.com/", InboundID: "in", SourceIP: tc.source})
		if err != nil || result.RequiresMITM != tc.mitm {
			t.Fatalf("source=%q result=%+v err=%v", tc.source, result, err)
		}
	}
}
