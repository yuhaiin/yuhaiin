package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type interceptRule struct {
	config  contract.Interception
	sources []netip.Prefix
}

// InterceptGateway admits only the Gateway chosen by the existing L4 Route.
func (m *Manager) InterceptGateway(ctx *netapi.Context, meta *netapi.StreamMeta, id string) bool {
	if id == "" {
		return false
	}
	snapshot := m.current.Load()
	if snapshot.startupError != "" {
		// A Route explicitly selected this failed Gateway. Returning false here
		// would silently bypass its policy through ordinary forwarding.
		if meta.Src != nil {
			_ = meta.Src.Close()
		}
		return true
	}
	if entry := snapshot.gateways[id]; entry != nil && !entry.engine.config.Enabled && entry.engine.config.RejectWhenDisabled {
		if meta.Src != nil {
			_ = meta.Src.Close()
		}
		return true
	}
	return m.intercept(ctx, meta, id, snapshot)
}

func (m *Manager) intercept(ctx *netapi.Context, meta *netapi.StreamMeta, gatewayID string, s *snapshot) bool {
	if len(s.interceptionByGateway) == 0 {
		return false
	}
	if m.internalSource(meta.Source) {
		_ = meta.Src.Close()
		return true
	}
	selected := s.interceptionByGateway[gatewayID]
	if selected == nil {
		return false
	}
	config := selected.config
	if len(config.Ports) > 0 && !slices.Contains(config.Ports, meta.Address.Port()) {
		return false
	}
	if len(selected.sources) > 0 && !sourceMatches(ctx.Source, selected.sources) {
		return false
	}
	if ctx.GetProcessName() != "" && len(config.Processes) > 0 && !slices.Contains(config.Processes, ctx.GetProcessName()) {
		return false
	}
	// A sniffed TLS name can be ECH's public_name, not the origin.
	// Postpone this check until after destination recovery so the allowed
	// original FQDN can authorize an ECH outer handshake.
	sniffHost := hostname(ctx.SniffHost())
	destination := meta.Address
	if destination.IsFqdn() && !matchesDomains(hostname(destination.Hostname()), config.Domains, config.ExcludeDomains) {
		return false
	}
	if m.recoverDestination != nil {
		destination = m.recoverDestination(ctx, destination)
	}
	if destination.IsFqdn() && !matchesDomains(hostname(destination.Hostname()), config.Domains, config.ExcludeDomains) {
		return false
	}
	if sniffHost != "" && !matchesDomains(sniffHost, config.Domains, config.ExcludeDomains) &&
		(config.Mode != "https_mitm" || !destination.IsFqdn() ||
			!matchesDomains(hostname(destination.Hostname()), config.Domains, config.ExcludeDomains)) {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	g := s.gateways[config.GatewayID]
	// Admission has already matched the Gateway selected by Routing and its configured limits.
	// Unselected TCP and all UDP traffic never allocate this reader or wait here.
	reader := bufio.NewReaderSize(meta.Src, 4<<10)
	replay := &readerConn{Conn: meta.Src, reader: reader}
	meta.Src = replay
	_ = meta.Src.SetReadDeadline(time.Now().Add(10 * time.Second))
	first, err := reader.Peek(1)
	if err != nil {
		_ = meta.Src.SetReadDeadline(time.Time{})
		return false
	}
	if first[0] == 0x16 {
		if config.Mode != "https_mitm" {
			_ = meta.Src.SetReadDeadline(time.Time{})
			return false
		}
		capture := &helloCapture{Conn: replay, remaining: 64 << 10}
		var hello *tls.ClientHelloInfo
		probe := tls.Server(capture, &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) { hello = chi; return nil, errHelloCaptured }})
		_ = probe.HandshakeContext(ctx)
		meta.Src = &readerConn{Conn: replay, reader: io.MultiReader(bytes.NewReader(capture.bytes.Bytes()), replay)}
		_ = meta.Src.SetReadDeadline(time.Time{})
		host := ""
		if hello != nil {
			host = hostname(hello.ServerName)
		}
		if host == "" {
			host = hostname(destination.Hostname())
		}
		// With real ECH, host is the public name, not the private origin.
		// Admit an unmatched public name only when an independently allowed
		// FQDN was selected by L4 routing or recovered from its destination.
		// Never override explicit domain exclusions.
		// GREASE is intentionally indistinguishable from real ECH; requiring
		// the distinct allowed destination limits this special admission.
		echRetryCandidate := hello != nil &&
			slices.Contains(hello.Extensions, uint16(0xfe0d)) &&
			destination.IsFqdn() &&
			host != "" && host != hostname(destination.Hostname()) &&
			matchesDomains(hostname(destination.Hostname()), config.Domains, config.ExcludeDomains) &&
			matchesDomains(host, nil, config.ExcludeDomains)
		if !matchesDomains(host, config.Domains, config.ExcludeDomains) && !echRetryCandidate {
			return false
		}
		httpALPN := hello != nil && (slices.Contains(hello.SupportedProtos, "h2") ||
			slices.Contains(hello.SupportedProtos, "http/1.1"))
		// The outer ALPN can hide HTTP. Allow the approved ECH outer
		// handshake to complete so the client can authenticate public_name
		// and retry; keep normal unknownTls behavior for other traffic.
		if hello == nil || (!httpALPN && !echRetryCandidate) {
			g.engine.Counters.ProtocolFailures.Add(1)
			log.Debug("gateway TLS admission", "gateway", config.GatewayID, "reason", "unsupported_client_hello", "action", config.UnknownTLS)
			if config.UnknownTLS == "reject" {
				_ = meta.Src.Close()
				return true
			}
			return false
		}
		if !m.admitProcess(ctx, destination, selected, g.engine.policy.needsProcess) {
			return false
		}
		certificate, err := m.Authority.Certificate(host)
		if err != nil {
			g.engine.Counters.TLSFailures.Add(1)
			log.Debug("gateway TLS interception failed", "gateway", config.GatewayID, "reason", "certificate_unavailable")
			_ = meta.Src.Close()
			return true
		}
		ctx.SetTLSServerName(host).SetProtocol("tls")
		nextProtos := []string{"h2", "http/1.1"}
		if !httpALPN {
			nextProtos = nil // The ECH rejection-only handshake must not require HTTP ALPN.
		}
		tlsConn := tls.Server(meta.Src, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*certificate}, NextProtos: nextProtos})
		_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			g.engine.Counters.TLSFailures.Add(1)
			log.Debug("gateway TLS interception failed", "gateway", config.GatewayID, "reason", "handshake_failed")
			_ = tlsConn.Close()
			return true
		}
		_ = tlsConn.SetDeadline(time.Time{})
		// Once the real handshake starts there is no passthrough fallback.
		m.serveIntercepted(ctx, g.engine, tlsConn, Metadata{Context: ctx, OriginalDestination: destination, Authority: host, Scheme: "https"})
		return true
	}
	if sniffHost != "" && !matchesDomains(sniffHost, config.Domains, config.ExcludeDomains) {
		_ = meta.Src.SetReadDeadline(time.Time{})
		return false // Plaintext must not inherit the ECH-specific sniff-name exception.
	}
	if !strings.ContainsRune("GHPDOTC", rune(first[0])) {
		_ = meta.Src.SetReadDeadline(time.Time{})
		return false
	}
	// Only HTTP/1 request lines are accepted on plaintext streams. HTTP/2
	// prior knowledge is deliberately passed through, never parsed as HTTP/1.
	header, err := probeHTTPHeader(reader)
	meta.Src = &readerConn{Conn: replay, reader: io.MultiReader(bytes.NewReader(header), reader)}
	_ = meta.Src.SetReadDeadline(time.Time{})
	if err != nil {
		return false
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if err != nil {
		return false
	}
	_ = request.Body.Close()
	if !matchesDomains(hostname(request.Host), config.Domains, config.ExcludeDomains) {
		return false
	}
	if !m.admitProcess(ctx, destination, selected, g.engine.policy.needsProcess) {
		return false
	}
	ctx.SetHTTPHost(hostname(request.Host)).SetProtocol("http")
	m.serveIntercepted(ctx, g.engine, meta.Src, Metadata{Context: ctx, OriginalDestination: destination, Authority: request.Host, Scheme: "http"})
	return true
}

func sourceMatches(source net.Addr, prefixes []netip.Prefix) bool {
	ip, ok := sourceIP(source)
	if !ok {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *Manager) admitProcess(ctx *netapi.Context, destination netapi.Address, rule *interceptRule, policyNeedsProcess bool) bool {
	if ctx.GetProcessName() == "" && (len(rule.config.Processes) > 0 || policyNeedsProcess) && m.lookupProcess != nil {
		m.lookupProcess(ctx, destination)
	}
	return len(rule.config.Processes) == 0 || slices.Contains(rule.config.Processes, ctx.GetProcessName())
}

func matchesDomains(host string, include, exclude []string) bool {
	for _, d := range exclude {
		if domainMatches(host, hostname(strings.TrimPrefix(d, "*."))) {
			return false
		}
	}
	if len(include) == 0 {
		return true
	}
	for _, d := range include {
		if domainMatches(host, hostname(strings.TrimPrefix(d, "*."))) {
			return true
		}
	}
	return false
}

var errHelloCaptured = errors.New("ClientHello captured")

type helloCapture struct {
	net.Conn
	bytes     bytes.Buffer
	remaining int
}

func (c *helloCapture) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errors.New("ClientHello exceeds capture limit")
	}
	n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	_, _ = c.bytes.Write(p[:n])
	return n, err
}

// The speculative TLS parser can emit alerts, but they never reach the client.
func (c *helloCapture) Write(p []byte) (int, error) { return len(p), nil }

type readerConn struct {
	net.Conn
	reader io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func probeHTTPHeader(reader *bufio.Reader) ([]byte, error) {
	var data []byte
	firstLine := true
	for len(data) < 64<<10 {
		line, err := reader.ReadSlice('\n')
		data = append(data, line...)
		if len(data) > 64<<10 {
			return data, errors.New("HTTP header exceeds probe limit")
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return data, err
		}
		if firstLine {
			firstLine = false
			parts := strings.Split(strings.TrimSuffix(string(data), "\r\n"), " ")
			if len(parts) != 3 || !slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}, parts[0]) || parts[2] != "HTTP/1.1" {
				return data, errors.New("not HTTP/1.1")
			}
		}
		if bytes.Equal(line, []byte("\r\n")) {
			return data, nil
		}
	}
	return data, errors.New("HTTP header exceeds probe limit")
}

type singleListener struct {
	conn     net.Conn
	done     chan struct{}
	once     sync.Once
	accepted bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *singleListener) Addr() net.Addr { return l.conn.LocalAddr() }

func (m *Manager) serveIntercepted(ctx context.Context, engine *Engine, conn net.Conn, meta Metadata) {
	m.sessionsMu.Lock()
	session := interceptSession{gatewayID: engine.config.ID, mitm: meta.Scheme == "https", host: hostname(meta.Authority), process: meta.Context.GetProcessName(), port: uint16(meta.OriginalDestination.Port())}
	if meta.OriginalDestination.IsFqdn() {
		session.destinationHost = hostname(meta.OriginalDestination.Hostname())
	}
	if source := meta.Context.Source; source != nil {
		if address, err := netip.ParseAddrPort(source.String()); err == nil {
			session.source = address.Addr().Unmap()
		}
	}
	if m.sessionsClosed || !sessionAllowed(m.current.Load(), session) {
		m.sessionsMu.Unlock()
		_ = conn.Close()
		return
	}
	m.sessions[conn] = session
	m.sessionsMu.Unlock()
	defer func() { _ = conn.Close(); m.sessionsMu.Lock(); delete(m.sessions, conn); m.sessionsMu.Unlock() }()
	// Preserve the concrete *tls.Conn: net/http uses it for ALPN and r.TLS.
	listener := &singleListener{conn: conn, done: make(chan struct{})}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	var hijacked atomic.Bool
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20, Protocols: protocols, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if hijacked.Load() {
				_ = listener.Close()
			}
		}()
		snapshot := m.current.Load()
		current := snapshot.gateways[engine.config.ID]
		if !sessionAllowed(snapshot, session) {
			http.Error(w, "gateway disabled", http.StatusServiceUnavailable)
			return
		}
		current.engine.ServeHTTP(w, r)
	}),
		ConnContext: func(_ context.Context, _ net.Conn) context.Context { return WithMetadata(ctx, meta) },
	}
	// Wrapping *tls.Conn to observe Close would hide it from net/http. Use
	// ConnState instead to release the listener after the real connection closes.
	server.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			_ = listener.Close()
		}
		if state == http.StateHijacked {
			hijacked.Store(true)
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = server.Close(); _ = conn.Close() })
	defer stop()
	_ = server.Serve(listener)
}
