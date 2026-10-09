package diagnostics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type streamFunc func(context.Context, netapi.Address) (net.Conn, error)

func (f streamFunc) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return f(ctx, addr)
}

func checkByID(t *testing.T, report tools.DiagnosticReport, id string) tools.DiagnosticCheck {
	t.Helper()
	for _, c := range report.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %q is missing", id)
	return tools.DiagnosticCheck{}
}

func TestNormalizeHost(t *testing.T) {
	for _, host := range []string{".", "https://example.com", "example.com:443", "example.com/path", "1.1.1.1", "::1", "foo..com", "-a.example", "a-.example", "local", "a@example.com", strings.Repeat("a", 64) + ".com", "example.com\nsecret"} {
		if _, err := NormalizeHost(host); !errors.Is(err, ErrInvalidHost) {
			t.Errorf("%q: %v", host, err)
		}
	}
	if host, err := NormalizeHost(" Example.COM. "); err != nil || host != "example.com" {
		t.Fatalf("%q: %v", host, err)
	}
	if host, err := NormalizeHost(""); err != nil || host != DefaultHost {
		t.Fatalf("%q: %v", host, err)
	}
}

func TestReportEvidenceAndPrivacy(t *testing.T) {
	var lookups atomic.Int32
	var dials atomic.Int32
	service := New(Dependencies{
		IPv6Enabled: func() bool { return false },
		TUN: func(context.Context) ([]TUNState, error) {
			return []TUNState{{Enabled: true, Running: false, Driver: "gvisor", MTU: 1500}}, nil
		},
		Lookup: func(_ context.Context, host string, ipv6 bool) ([]string, error) {
			lookups.Add(1)
			if ipv6 {
				t.Error("disabled IPv6 must not query AAAA")
			}
			if host != "example.com" {
				t.Errorf("unexpected host %q", host)
			}
			return []string{"192.0.2.1"}, nil
		},
		Direct: streamFunc(func(_ context.Context, addr netapi.Address) (net.Conn, error) {
			dials.Add(1)
			if addr.Hostname() != "1.1.1.1" {
				t.Errorf("unexpected direct target %s", addr)
			}
			return nil, context.DeadlineExceeded
		}),
		Routed: streamFunc(func(context.Context, netapi.Address) (net.Conn, error) {
			return nil, errors.New("secret-token https://user:password@private.node")
		}),
		Route: func(_ context.Context, host string) (contractroute.RuleTestResponse, error) {
			if host != "example.com:443" {
				t.Errorf("route input: %s", host)
			}
			return contractroute.RuleTestResponse{Mode: "block", Tag: "policy", Resolver: "resolver-1"}, nil
		},
	})
	report, err := service.Run(t.Context(), tools.DiagnosticRequest{Host: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) != 8 || lookups.Load() != 1 || dials.Load() != 1 {
		t.Fatalf("unexpected probes: %+v", report)
	}
	if checkByID(t, report, "tun").Message != "tun_not_running" {
		t.Fatal("missed enabled but absent listener")
	}
	if checkByID(t, report, "dns6").Status != "skipped" || checkByID(t, report, "ipv6").Status != "skipped" {
		t.Fatal("IPv6 not skipped")
	}
	if check := checkByID(t, report, "ipv4"); check.Message != "timeout" || !slices.Equal(check.Evidence, []string{"1.1.1.1:443"}) {
		t.Fatalf("failed direct probe must retain its attempted endpoint: %+v", check)
	}
	if checkByID(t, report, "route").Status != "warning" {
		t.Fatal("intentional blocking must be distinguished from a broken route")
	}
	if strings.Contains(report.Report, "secret-token") || strings.Contains(report.Report, "password") || strings.Contains(report.Report, "private.node") {
		t.Fatal("report leaked a raw dial error")
	}
	if !strings.Contains(report.Report, "Check TUN startup") || !strings.Contains(report.Report, "DNS") {
		t.Fatal("portable report needs readable guidance")
	}
	for _, c := range report.Checks {
		if c.Evidence == nil {
			t.Fatal("nil evidence breaks clients")
		}
	}
}

func TestBusyAndCancellation(t *testing.T) {
	entered := make(chan struct{})
	service := New(Dependencies{Lookup: func(ctx context.Context, _ string, _ bool) ([]string, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := service.Run(ctx, tools.DiagnosticRequest{}); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe not started")
	}
	if _, err := service.Run(t.Context(), tools.DiagnosticRequest{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent run: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled probes leaked")
	}
	// The lock must be released, even after cancellation.
	service.deps.Lookup = nil
	if _, err := service.Run(t.Context(), tools.DiagnosticRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSVerificationStatusAndNoRedirect(t *testing.T) {
	var redirectVisits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			redirectVisits.Add(1)
		}
		w.Header().Set("Location", "/redirect")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	proxy := streamFunc(func(ctx context.Context, _ netapi.Address) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	// Default production TLS settings must reject an untrusted certificate.
	if check := https(t.Context(), proxy, "example.com"); check.Message != "tls_verification_failed" {
		t.Fatal("TLS verification was bypassed or misclassified")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := newHTTPTransport(proxy)
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	// httptest's certificate includes example.com. HTTP 302 is still proof
	// of a verified response, and the probe must not follow redirects.
	check := requestHTTPS(t.Context(), transport, "example.com")
	if check.Status != "pass" || len(check.Evidence) != 1 || check.Evidence[0] != "HTTP 302" || redirectVisits.Load() != 0 {
		t.Fatalf("unexpected HTTPS result: %+v", check)
	}
}

func TestStalledTLSHonorsContext(t *testing.T) {
	peer := make(chan net.Conn, 1)
	proxy := streamFunc(func(context.Context, netapi.Address) (net.Conn, error) { a, b := net.Pipe(); peer <- b; return a, nil })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	check := https(ctx, proxy, "example.com")
	_ = (<-peer).Close()
	if check.Message != "timeout" {
		t.Fatalf("stalled TLS: %+v", check)
	}
}

func TestFindingsDoNotOverclaim(t *testing.T) {
	cases := []struct {
		checks       []tools.DiagnosticCheck
		want, absent string
	}{
		{[]tools.DiagnosticCheck{{ID: "dns4", Status: "fail"}, {ID: "dns6", Status: "pass"}}, "scope_limit", "check_dns"},
		{[]tools.DiagnosticCheck{{ID: "ipv4", Status: "pass"}, {ID: "ipv6", Status: "skipped"}}, "scope_limit", "ipv6_path_failed"},
		{[]tools.DiagnosticCheck{{ID: "routed_https", Status: "pass"}}, "core_path_works", "check_tun_start"},
		{[]tools.DiagnosticCheck{{ID: "node", Status: "pass"}, {ID: "routed_https", Status: "fail"}}, "check_route_path", "check_selected_node"},
		{[]tools.DiagnosticCheck{{ID: "node", Status: "skipped", Message: "no_selected_node"}, {ID: "route", Status: "pass", Message: "route_selected_node"}}, "select_tcp_node", "check_selected_node"},
		{[]tools.DiagnosticCheck{{ID: "tun", Status: "fail", Message: "probe_failed"}}, "scope_limit", "check_tun_start"},
	}
	for _, tc := range cases {
		out := findings(tc.checks)
		if !slices.Contains(out, tc.want) || slices.Contains(out, tc.absent) {
			t.Errorf("findings %q want %s absent %s", out, tc.want, tc.absent)
		}
	}
}
