// Package diagnostics runs bounded, on-demand probes shared by all clients.
package diagnostics

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const DefaultHost = "www.cloudflare.com"
const probeTimeout = 6 * time.Second

var ErrBusy = errors.New("a network diagnosis is already running")
var ErrInvalidHost = errors.New("enter a DNS hostname without a scheme, port or path")

type TUNState struct {
	Enabled bool
	Running bool
	Driver  string
	MTU     int32
	Streams uint64
	Packets uint64
	Pings   uint64
}

type Dependencies struct {
	TUN           func(context.Context) ([]TUNState, error)
	Lookup        func(context.Context, string, bool) ([]string, error)
	Direct        netapi.StreamProxy
	Routed        netapi.StreamProxy
	Route         func(context.Context, string) (contractroute.RuleTestResponse, error)
	SelectedProxy func(context.Context) (netapi.StreamProxy, error)
	IPv6Enabled   func() bool
}

type Service struct {
	deps Dependencies
	mu   sync.Mutex
}

func New(deps Dependencies) *Service { return &Service{deps: deps} }

func NormalizeHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return DefaultHost, nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) > 253 || !strings.Contains(host, ".") {
		return "", ErrInvalidHost
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", ErrInvalidHost
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidHost
		}
		for _, c := range label {
			valid := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
			if !valid {
				return "", ErrInvalidHost
			}
		}
	}
	return host, nil
}

func (s *Service) Run(ctx context.Context, request tools.DiagnosticRequest) (tools.DiagnosticReport, error) {
	host, err := NormalizeHost(request.Host)
	if err != nil {
		return tools.DiagnosticReport{}, err
	}
	if !s.mu.TryLock() {
		return tools.DiagnosticReport{}, ErrBusy
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	started := time.Now()
	ipv6 := s.deps.IPv6Enabled != nil && s.deps.IPv6Enabled()
	report := tools.DiagnosticReport{SchemaVersion: 1, StartedAt: started.UTC().Format(time.RFC3339), Host: host, Platform: runtime.GOOS + "/" + runtime.GOARCH, Version: version.Version, IPv6Enabled: ipv6}
	jobs := []struct {
		id  string
		run func(context.Context) tools.DiagnosticCheck
	}{
		{"tun", s.tun},
		{"dns4", func(ctx context.Context) tools.DiagnosticCheck { return s.dns(ctx, host, false) }},
		{"dns6", func(ctx context.Context) tools.DiagnosticCheck {
			if !ipv6 {
				return result("skipped", "ipv6_disabled")
			}
			return s.dns(ctx, host, true)
		}},
		{"ipv4", func(ctx context.Context) tools.DiagnosticCheck { return connect(ctx, s.deps.Direct, "1.1.1.1:443") }},
		{"ipv6", func(ctx context.Context) tools.DiagnosticCheck {
			if !ipv6 {
				return result("skipped", "ipv6_disabled")
			}
			return connect(ctx, s.deps.Direct, "[2606:4700:4700::1111]:443")
		}},
		{"route", func(ctx context.Context) tools.DiagnosticCheck { return s.route(ctx, host) }},
		{"routed_https", func(ctx context.Context) tools.DiagnosticCheck { return https(ctx, s.deps.Routed, host) }},
		{"node", func(ctx context.Context) tools.DiagnosticCheck {
			if s.deps.SelectedProxy == nil {
				return result("skipped", "unavailable")
			}
			proxy, err := s.deps.SelectedProxy(ctx)
			if err != nil {
				return failure(err)
			}
			if proxy == nil {
				return result("skipped", "no_selected_node")
			}
			return https(ctx, proxy, host)
		}},
	}
	report.Checks = make([]tools.DiagnosticCheck, len(jobs))
	var wg sync.WaitGroup
	for i, job := range jobs {
		wg.Go(func() {
			begin := time.Now()
			probeCtx, stop := context.WithTimeout(ctx, probeTimeout)
			defer stop()
			// Each probe owns its routing metadata; never share mutable netapi contexts.
			check := job.run(netapi.WithContext(probeCtx))
			check.ID = job.id
			check.DurationMS = time.Since(begin).Milliseconds()
			if check.Evidence == nil {
				check.Evidence = []string{}
			}
			report.Checks[i] = check
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return tools.DiagnosticReport{}, err
	}
	report.DurationMS = time.Since(started).Milliseconds()
	report.Findings = findings(report.Checks)
	report.Report = render(report)
	return report, nil
}

func result(status, message string, evidence ...string) tools.DiagnosticCheck {
	return tools.DiagnosticCheck{Status: status, Message: message, Evidence: evidence}
}

// Raw dialer errors can contain node URLs, addresses or credentials. Keep them
// out of the report; expose only safe error categories.
func failure(err error) tools.DiagnosticCheck {
	message := "probe_failed"
	if errors.Is(err, context.DeadlineExceeded) {
		message = "timeout"
	} else if errors.Is(err, context.Canceled) {
		message = "canceled"
	} else if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		message = "tls_verification_failed"
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		message = "connection_refused"
	} else if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		message = "network_unreachable"
	} else if _, ok := errors.AsType[*net.DNSError](err); ok {
		message = "dns_failed"
	} else if netapi.IsBlockError(err) {
		message = "blocked"
	} else if e, ok := errors.AsType[net.Error](err); ok && e.Timeout() {
		message = "timeout"
	}
	return result("fail", message)
}

func (s *Service) tun(ctx context.Context) tools.DiagnosticCheck {
	if s.deps.TUN == nil {
		return result("skipped", "unavailable")
	}
	states, err := s.deps.TUN(ctx)
	if err != nil {
		return failure(err)
	}
	if len(states) == 0 {
		return result("skipped", "no_tun")
	}
	check := result("skipped", "tun_disabled")
	for i, state := range states {
		check.Evidence = append(check.Evidence, fmt.Sprintf("TUN %d: enabled=%t, listener_registered=%t, driver=%s, mtu=%d, streams=%d, packets=%d, pings=%d (since listener start)", i+1, state.Enabled, state.Running, state.Driver, state.MTU, state.Streams, state.Packets, state.Pings))
		if state.Enabled {
			if !state.Running {
				check.Status, check.Message = "fail", "tun_not_running"
			} else if check.Status != "fail" {
				check.Status, check.Message = "warning", "tun_capture_unverified"
			}
		}
	}
	return check
}

func (s *Service) dns(ctx context.Context, host string, ipv6 bool) tools.DiagnosticCheck {
	if s.deps.Lookup == nil {
		return result("skipped", "unavailable")
	}
	ips, err := s.deps.Lookup(ctx, host, ipv6)
	if err != nil {
		return failure(err)
	}
	if len(ips) == 0 {
		return result("warning", "no_dns_records")
	}
	return result("pass", "dns_resolved", ips...)
}

func connect(ctx context.Context, proxy netapi.StreamProxy, target string) tools.DiagnosticCheck {
	if proxy == nil {
		return result("skipped", "unavailable")
	}
	addr, err := netapi.ParseAddress("tcp", target)
	if err != nil {
		return failure(err)
	}
	conn, err := proxy.Conn(ctx, addr)
	if err != nil {
		check := failure(err)
		check.Evidence = []string{target}
		return check
	}
	_ = conn.Close()
	return result("pass", "tcp_connected", target)
}

func https(ctx context.Context, proxy netapi.StreamProxy, host string) tools.DiagnosticCheck {
	if proxy == nil {
		return result("skipped", "unavailable")
	}
	return requestHTTPS(ctx, newHTTPTransport(proxy), host)
}

func newHTTPTransport(proxy netapi.StreamProxy) *http.Transport {
	return &http.Transport{DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		addr, err := netapi.ParseAddress(network, address)
		if err != nil {
			return nil, err
		}
		return proxy.Conn(netapi.WithContext(ctx), addr)
	}}
}

func requestHTTPS(ctx context.Context, transport *http.Transport, host string) tools.DiagnosticCheck {
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return failure(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return failure(err)
	}
	_ = resp.Body.Close()
	// Even a 403/500 proves TCP, TLS verification and a response from this
	// endpoint. Its application status is evidence, not a broken-node verdict.
	return result("pass", "https_response", fmt.Sprintf("HTTP %d", resp.StatusCode))
}

func (s *Service) route(ctx context.Context, host string) tools.DiagnosticCheck {
	if s.deps.Route == nil {
		return result("skipped", "unavailable")
	}
	route, err := s.deps.Route(ctx, net.JoinHostPort(host, "443"))
	if err != nil {
		return failure(err)
	}
	status, message := "pass", "route_matched"
	if route.Mode == "proxy" && route.Tag == "" {
		message = "route_selected_node"
	}
	if route.Mode == "block" {
		status, message = "warning", "route_blocks_target"
	}
	return result(status, message, "mode="+route.Mode, "tag="+route.Tag, "resolver="+route.Resolver, "destination="+route.AfterAddr)
}

func findings(checks []tools.DiagnosticCheck) []string {
	byID := make(map[string]tools.DiagnosticCheck, len(checks))
	for _, c := range checks {
		byID[c.ID] = c
	}
	out := []string{}
	if byID["tun"].Message == "tun_not_running" {
		out = append(out, "check_tun_start")
	}
	if byID["dns4"].Status == "fail" && byID["dns6"].Status != "pass" {
		out = append(out, "check_dns")
	}
	if byID["dns4"].Status == "fail" && byID["dns6"].Status == "pass" {
		out = append(out, "check_dns4")
	}
	if byID["dns6"].Status == "fail" && byID["dns4"].Status == "pass" {
		out = append(out, "check_dns6")
	}
	if byID["ipv4"].Status == "fail" && byID["ipv6"].Status != "pass" {
		out = append(out, "check_direct_path")
	}
	if byID["ipv4"].Status == "fail" && byID["ipv6"].Status == "pass" {
		out = append(out, "ipv4_path_failed")
	}
	if byID["ipv6"].Status == "fail" && byID["ipv4"].Status == "pass" {
		out = append(out, "ipv6_path_failed")
	}
	if byID["route"].Message == "route_blocks_target" {
		out = append(out, "check_route_block")
	}
	if byID["route"].Message == "route_selected_node" && byID["node"].Message == "no_selected_node" {
		out = append(out, "select_tcp_node")
	}
	if byID["routed_https"].Status == "fail" && byID["node"].Status != "pass" && byID["route"].Message != "route_blocks_target" {
		out = append(out, "check_routed_https")
	}
	if byID["node"].Status == "fail" {
		out = append(out, "check_selected_node")
	}
	if byID["routed_https"].Status == "fail" && byID["node"].Status == "pass" {
		out = append(out, "check_route_path")
	}
	if byID["routed_https"].Status == "pass" {
		out = append(out, "core_path_works")
	}
	out = append(out, "scope_limit")
	return out
}

func render(report tools.DiagnosticReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Yuhaiin network diagnostic report (schema %d)\nTime: %s\nPlatform: %s\nVersion: %s\nTarget: %s:443\nIPv6 enabled: %t\nDuration: %d ms\n", report.SchemaVersion, report.StartedAt, report.Platform, report.Version, report.Host, report.IPv6Enabled, report.DurationMS)
	for _, c := range report.Checks {
		fmt.Fprintf(&b, "\n[%s] %s: %s (%d ms)\n", c.Status, c.ID, explanation(c.Message), c.DurationMS)
		for _, evidence := range c.Evidence {
			fmt.Fprintf(&b, "  %s\n", evidence)
		}
	}
	b.WriteString("\nFindings and next steps:\n")
	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "- %s\n", explanation(finding))
	}
	b.WriteString("\nScope: probes run in the core on the backend device. Direct IP probes measure TCP reachability to one fixed endpoint per family. HTTPS probes verify TLS and an HTTP response for the target. TUN traffic capture, OS routes, browser DNS, UDP and other destinations are not proven by these probes. A failed probe is evidence for this target and time, not proof that a component is broken. No node configurations, credentials or raw logs are included.\n")
	return b.String()
}
