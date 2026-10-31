package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func admissionConfig() contract.Config {
	return contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "forward"}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "http_only", Domains: []string{"example.com"}, ExcludeDomains: []string{"excluded.example.com"}, Ports: []uint16{80, 443}}}}
}

func TestAdmissionRejectsBeforeProbingOrProcessLookup(t *testing.T) {
	for _, tc := range []struct {
		name, destination, gateway string
		source                     netip.Addr
		process                    bool
		mode                       string
		disabled, recovered        bool
	}{
		{name: "unrelated domain", destination: "other.example:443"},
		{name: "excluded domain", destination: "excluded.example.com:443"},
		{name: "other gateway", destination: "example.com:443", gateway: "other"},
		{name: "wrong port", destination: "example.com:8443"},
		{name: "source before process", destination: "example.com:443", source: netip.MustParseAddr("192.0.2.1"), process: true},
		{name: "domain before process", destination: "other.example:443", process: true},
		{name: "recovered domain", destination: "198.18.0.1:443", recovered: true},
		{name: "passthrough", destination: "example.com:443", mode: "tls_passthrough", process: true},
		{name: "disabled gateway", destination: "example.com:443", disabled: true, process: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := admissionConfig()
			if tc.process {
				config.Interceptions[0].Processes = []string{"spotify"}
			}
			if tc.source.IsValid() {
				config.Interceptions[0].Sources = []string{"127.0.0.0/8"}
			}
			if tc.mode != "" {
				config.Interceptions[0].Mode = tc.mode
			}
			config.Gateways[0].Enabled = !tc.disabled
			m, _ := newTestManager(t, config, nil)
			lookups, recoveries := 0, 0
			m.lookupProcess = func(context.Context, netapi.Address) { lookups++ }
			m.recoverDestination = func(_ context.Context, a netapi.Address) netapi.Address {
				recoveries++
				if tc.recovered {
					v, _ := netapi.ParseAddress("tcp", "other.example:443")
					return v
				}
				return a
			}
			address, _ := netapi.ParseAddress("tcp", tc.destination)
			conn := new(failOnReadConn)
			meta := &netapi.StreamMeta{Src: conn, Address: address}
			gatewayID := tc.gateway
			if gatewayID == "" {
				gatewayID = "g"
			}
			ctx := netapi.WithContext(t.Context()).SetInboundID("in")
			if tc.source.IsValid() {
				ctx.Source = net.TCPAddrFromAddrPort(netip.AddrPortFrom(tc.source, 1234))
			}
			if m.InterceptGateway(ctx, meta, gatewayID) || conn.read || lookups != 0 {
				t.Fatalf("read=%t process lookups=%d", conn.read, lookups)
			}
			if tc.recovered && recoveries != 1 {
				t.Fatalf("recoveries=%d", recoveries)
			}
			if meta.Src != conn {
				t.Fatal("bypassed connection was wrapped")
			}
		})
	}
}

func TestFilterSkipsUnrelatedHostWithoutBuildingURI(t *testing.T) {
	filter, err := CompileFilters([]contract.FilterList{{ID: "f", Enabled: true, Text: "||ads.example/ads/*"}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "https://other.example/long/path?tracking="+strings.Repeat("x", 4096), nil)
	allocations := testing.AllocsPerRun(100, func() {
		if filter.blocked(request) {
			t.Fatal("unrelated host blocked")
		}
	})
	if allocations != 0 {
		t.Fatalf("unrelated filter allocated %g times", allocations)
	}
}

func TestGatewayOnlyStartsHealthForReferencedUpstreams(t *testing.T) {
	config := admissionConfig()
	config.Upstreams = []contract.Upstream{{ID: "unused", HealthPath: "/health", Backends: []contract.Backend{{URL: "http://unused.invalid"}}}}
	m, _ := newTestManager(t, config, nil)
	engine := m.current.Load().gateways["g"].engine
	if engine.healthCancel != nil || len(engine.upstreams) != 0 {
		t.Fatal("forward-only Gateway owns unused upstream health work")
	}
	if status := m.Status(); len(status.Gateways[0].Upstreams) != 0 {
		t.Fatal("unused upstream reported for Gateway")
	}
	// Unused drafts must still be validated globally.
	draft := m.Config()
	draft.Upstreams[0].Backends[0].URL = "invalid"
	if _, err := m.Save(t.Context(), draft); err == nil {
		t.Fatal("invalid unused upstream accepted")
	}
}

func BenchmarkAdmissionBypass(b *testing.B) {
	for _, tc := range []struct{ name, destination, gateway string }{{"KnownDomain", "other.example:443", "g"}, {"ExcludedDomain", "excluded.example.com:443", "g"}, {"OtherGateway", "example.com:443", "other"}, {"OtherPort", "example.com:8443", "g"}} {
		b.Run(tc.name, func(b *testing.B) {
			m, _ := newTestManager(b, admissionConfig(), nil)
			address, _ := netapi.ParseAddress("tcp", tc.destination)
			conn := new(failOnReadConn)
			meta := &netapi.StreamMeta{Src: conn, Address: address}
			ctx := netapi.WithContext(b.Context()).SetInboundID("in")
			ctx.Source = net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1234"))
			meta.Source = ctx.Source
			b.ReportAllocs()
			for b.Loop() {
				meta.Src = conn
				if m.InterceptGateway(ctx, meta, tc.gateway) {
					b.Fatal("unexpected interception")
				}
			}
		})
	}
}

func BenchmarkAdmissionImportedGuard(b *testing.B) {
	config := admissionConfig()
	config.Gateways[0].Enabled = false
	config.Gateways[0].RejectWhenDisabled = true
	m, _ := newTestManager(b, config, nil)
	address, _ := netapi.ParseAddress("tcp", "example.com:443")
	conn := new(failOnReadConn)
	meta := &netapi.StreamMeta{Src: conn, Address: address}
	ctx := netapi.WithContext(b.Context())
	b.ReportAllocs()
	for b.Loop() {
		if !m.InterceptGateway(ctx, meta, "g") {
			b.Fatal("imported Gateway did not reject traffic")
		}
	}
}

func TestAdmissionRechecksSniffedHostBeforeAllocatingProbe(t *testing.T) {
	m, _ := newTestManager(t, admissionConfig(), nil)
	address, _ := netapi.ParseAddress("tcp", "192.0.2.1:443")
	conn := new(failOnReadConn)
	meta := &netapi.StreamMeta{Src: conn, Address: address}
	ctx := netapi.WithContext(t.Context()).SetInboundID("in").SetTLSServerName("other.example")
	if m.InterceptGateway(ctx, meta, "g") || conn.read || meta.Src != conn {
		t.Fatal("known excluded SNI was probed again")
	}
}
func TestHTTPProbePreservesLongHeaderLines(t *testing.T) {
	m, _ := newTestManager(t, contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "g", Enabled: true, Default: contract.Action{Type: "respond", Body: "ok"}}}, Interceptions: []contract.Interception{{GatewayID: "g", Mode: "http_only", Domains: []string{"example.com"}}}}, nil)
	address, _ := interceptListener(t, m, "192.0.2.1:80", "127.0.0.1:1")
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, "tcp", address)
	}}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(t.Context(), "GET", "http://example.com/", nil)
	request.Header.Set("X-Large", strings.Repeat("x", 12<<10))
	response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "ok" {
		t.Fatalf("long header bypassed Gateway: %s", body)
	}
}
