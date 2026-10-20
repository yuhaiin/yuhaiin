package inbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	gatewaycontract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	inboundcontract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	routecontract "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

type gatewayRouteDialer struct {
	netapi.Proxy
	destination string
}

func (d gatewayRouteDialer) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	return new(net.Dialer).DialContext(ctx, "tcp", d.destination)
}
func (d gatewayRouteDialer) GetTarget(_ context.Context, _ string, mode string, _ routecontract.Target) (netapi.Proxy, error) {
	if mode == "block" {
		return netapi.NewErrProxy(errors.New("route blocked")), nil
	}
	return d, nil
}

type gatewayResolverBook struct{}

func (gatewayResolverBook) Get(string, string) netapi.Resolver { return netapi.Bootstrap() }

func TestExistingRouteGatesHTTPAndMITMStreams(t *testing.T) {
	old := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(old) })
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "backend:"+r.URL.Path) }))
	defer backend.Close()
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	gs := store.NewGatewayStore(db.DB())
	authority, err := gateway.NewAuthority(t.Context(), gs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Generate(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	settings := store.NewRouteSettingsStore(db.DB())
	book := store.NewRouteRuleStore(db.DB())
	lists := route.NewLists(store.NewRouteListStore(db.DB()), settings, t.TempDir())
	defer lists.Close()
	router := route.NewRoute(gatewayRouteDialer{destination: strings.TrimPrefix(backend.URL, "http://")}, gatewayResolverBook{}, lists, nil)
	rules := route.NewRules(book, settings, router)
	defer rules.Close()
	manager, err := gateway.NewManager(t.Context(), gs, authority, func(ctx context.Context, address netapi.Address, target routecontract.Target) (gateway.Selection, error) {
		p, destination, err := router.ResolveTCP(route.WithoutGateway(ctx), address, target)
		return gateway.Selection{Proxy: p, Destination: destination, Identity: "route"}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	config := gatewaycontract.Config{Gateways: []gatewaycontract.Gateway{{ID: "g", Name: "g", Enabled: true, RuleIDs: []string{"ads"}, Default: gatewaycontract.Action{Type: "reverse_proxy", Upstream: "u"}}}, Rules: []gatewaycontract.Rule{{ID: "ads", Enabled: true, Match: gatewaycontract.Condition{Field: "path", Operator: "prefix", Value: "/ads/"}, Action: gatewaycontract.Action{Type: "block", Status: 204}}}, Upstreams: []gatewaycontract.Upstream{{ID: "u", Backends: []gatewaycontract.Backend{{URL: backend.URL}}}}, Interceptions: []gatewaycontract.Interception{{GatewayID: "g", Mode: "https_mitm", Domains: []string{"app.example"}, Ports: []uint16{80, 443}}}}
	if _, err = manager.Save(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	router.SetGatewayHandler(nil, manager.InterceptGateway)
	editor := store.NewRouteEditorStore(db.DB())
	draft, err := editor.Save(t.Context(), routecontract.RuleDraft{Rule: routecontract.RouteRule{ID: "g-rule", Name: "Gateway", Mode: "gateway", Target: routecontract.Target{Type: "gateway", ID: "g"}, Rules: []routecontract.RuleExpr{{Type: "host", Host: &routecontract.ListRef{List: "sites"}}}}, Lists: []routecontract.RouteListDetail{{ID: "sites", Name: "Sites", Type: "host", Source: routecontract.ListSource{Type: "local", Local: &routecontract.LocalSource{Lists: []string{"app.example"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(gatewayRouteDialer{destination: strings.TrimPrefix(backend.URL, "http://")})
	defer h.Close()
	h.dialer = router
	h.interceptor = router
	if err := h.control.Apply(trafficcontrol.Config{Enabled: true,
		Profiles: map[string]trafficcontrol.Profile{"gateway": {
			Upload:   trafficcontrol.Rate{BytesPerSecond: 1 << 20, BurstBytes: 65536},
			Download: trafficcontrol.Rate{BytesPerSecond: 1 << 20, BurstBytes: 65536},
		}}, RouteProfiles: map[string]string{"g-rule": "gateway"},
	}); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("inbound workers did not close")
		}
	})
	start := func(inboundID, host string, port uint16) string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Go(func() {
					ctx := netapi.WithContext(t.Context()).SetInboundID(inboundID)
					ctx.Source = conn.RemoteAddr()
					ctx.Destination = conn.LocalAddr()
					address, _ := netapi.ParseAddressPort("tcp", host, port)
					h.Stream(ctx, &netapi.StreamMeta{Src: conn, Address: address, Source: conn.RemoteAddr(), Destination: address})
				})
			}
		}()
		return listener.Addr().String()
	}
	appHTTP, appTLS, outside := start("http-in", "app.example", 80), start("tls-in", "app.example", 443), start("outside-in", "outside.example", 80)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(manager.CAStatus().CertificatePEM))
	transport := &http.Transport{DisableKeepAlives: true, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		chosen := appHTTP
		if strings.HasSuffix(address, ":443") {
			chosen = appTLS
		}
		if strings.HasPrefix(address, "outside.") {
			chosen = outside
		}
		return new(net.Dialer).DialContext(ctx, "tcp", chosen)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for _, test := range []struct {
		url  string
		code int
		body string
	}{{"http://app.example/ads/banner", 204, ""}, {"https://app.example/ok", 200, "backend:/ok"}, {"http://outside.example/ads/banner", 200, "backend:/ads/banner"}} {
		before := h.control.Usage()
		response, err := client.Get(test.url)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != test.code || string(body) != test.body {
			t.Fatalf("%s: %s %q", test.url, response.Status, body)
		}
		if strings.Contains(test.url, "app.example") {
			after := h.control.Usage()
			if after.AdmittedUploadBytes <= before.AdmittedUploadBytes || after.AdmittedDownloadBytes <= before.AdmittedDownloadBytes {
				t.Fatal("Gateway bypassed stream shaping", before, after)
			}
		}
		if strings.HasPrefix(test.url, "https:") && response.ProtoMajor != 2 {
			t.Fatal(response.Proto)
		}
	}
	if requests := manager.Status().Gateways[0].Requests; requests != 2 {
		t.Fatalf("unrelated traffic reached Gateway: %d", requests)
	}
	// Inbound admission belongs to Routing. The same Gateway setting needs no edit.
	// Only a Route Inbound condition needs a persisted reference.
	if err = store.NewInboundStore(db.DB()).Save(t.Context(), inboundcontract.Inbound{
		ID: "tls-in", Name: "TLS inbound",
		Network:  inboundcontract.NewTypedNetwork(inboundcontract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: inboundcontract.UDPTCPOnly}),
		Protocol: inboundcontract.NewTypedProtocol(inboundcontract.MixedProtocol{}),
	}, 0); err != nil {
		t.Fatal(err)
	}
	draft.Rule.Rules = []routecontract.RuleExpr{{Type: "all", All: []routecontract.RuleExpr{
		{Type: "host", Host: &routecontract.ListRef{List: "sites"}},
		{Type: "inbound", Inbound: &routecontract.SourceRef{Name: "tls-in"}},
	}}}
	if _, err = editor.Save(t.Context(), routecontract.RuleDraft{Rule: draft.Rule, Lists: draft.Lists}); err != nil {
		t.Fatal(err)
	}
	if err = rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("http://app.example/ads/banner")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || string(body) != "backend:/ads/banner" || manager.Status().Gateways[0].Requests != 2 {
		t.Fatal("Routing Inbound condition did not exclude HTTP inbound")
	}
	response, err = client.Get("https://app.example/ads/banner")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 204 || manager.Status().Gateways[0].Requests != 3 {
		t.Fatal("Routing Inbound condition did not retain TLS inbound")
	}
	// Gateway interception does nothing once its L4 action is gone.
	if err = book.DeleteRule(t.Context(), draft.Rule.ID); err != nil {
		t.Fatal(err)
	}
	if err = rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	response, err = client.Get("http://app.example/ads/banner")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || manager.Status().Gateways[0].Requests != 3 {
		t.Fatal("Gateway bypassed normal Route selection")
	}
	// Restore the selected Gateway route, then prove its profile actually paces
	// a response, rather than merely incrementing aggregate usage counters.
	draft.Rule.Revision = 0 // The rule was removed above.
	draft.Rule.Rules = []routecontract.RuleExpr{{Type: "host", Host: &routecontract.ListRef{List: "sites"}}}
	if _, err := editor.Save(t.Context(), routecontract.RuleDraft{Rule: draft.Rule, Lists: draft.Lists}); err != nil {
		t.Fatal(err)
	}
	if err := rules.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	original := h.control.Config()
	limited := h.control.Config()
	limited.Profiles["gateway"] = trafficcontrol.Profile{Download: trafficcontrol.Rate{BytesPerSecond: 1, BurstBytes: 1}}
	if err := h.control.Apply(limited); err != nil {
		t.Fatal(err)
	}
	// Release a paced writer promptly once this intentionally timed-out request
	// has demonstrated the cap; activation wakes the old waiter's policy loop.
	defer func() {
		if err := h.control.Apply(original); err != nil {
			t.Error(err)
		}
	}()
	before := h.control.Usage()
	requestCtx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://app.example/ok", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = client.Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Gateway route profile did not pace response: %v", err)
	}
	if delta := h.control.Usage().AdmittedDownloadBytes - before.AdmittedDownloadBytes; delta != 1 {
		t.Fatalf("Gateway did not enforce one-byte burst: admitted %d", delta)
	}

}
