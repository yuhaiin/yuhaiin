package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type metadataKey struct{}

// Metadata preserves connection identity separately from HTTP authority and the
// rewritten upstream. It is immutable after a connection is admitted.
type Metadata struct {
	Context             *netapi.Context
	OriginalDestination netapi.Address
	Authority           string
	Scheme              string
}

func WithMetadata(ctx context.Context, meta Metadata) context.Context {
	return context.WithValue(ctx, metadataKey{}, meta)
}

type Counters struct {
	Requests         atomic.Uint64
	Blocked          atomic.Uint64
	Forwarded        atomic.Uint64
	Errors           atomic.Uint64
	DurationNS       atomic.Uint64
	TLSFailures      atomic.Uint64
	ProtocolFailures atomic.Uint64
}

// Engine handles HTTP only. Listener admission, interception and CA lifecycle
// belong to separate modules.
type Engine struct {
	access         netapi.TrafficAccess
	filters        *filterPolicy
	healthCancel   context.CancelFunc
	healthWG       sync.WaitGroup
	config         contract.Gateway
	policy         *Policy
	upstreams      map[string]*upstream
	selectOutbound SelectOutbound
	pool           *TransportPool
	Counters       *Counters
	lastOutbound   atomic.Pointer[string]
	localAudit     func(*netapi.Context, string, bool)
}

func (e *Engine) auditLocal(ctx *netapi.Context, r *http.Request, blocked bool) {
	if e.localAudit == nil {
		return
	}
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		port := "80"
		if r.URL.Scheme == "https" || r.TLS != nil {
			port = "443"
		}
		target = net.JoinHostPort(strings.Trim(target, "[]"), port)
	}
	e.localAudit(ctx, target, blocked)
}

func NewEngine(config contract.Gateway, rules []contract.Rule, upstreams []contract.Upstream, selectOutbound SelectOutbound) (*Engine, error) {
	policy, err := CompilePolicy(rules, config.Default)
	if err != nil {
		return nil, err
	}
	e := &Engine{config: config, policy: policy, upstreams: make(map[string]*upstream), selectOutbound: selectOutbound, pool: NewTransportPool(256), Counters: new(Counters)}
	needed := make(map[string]bool)
	for _, action := range append([]contract.Action{policy.fallback}, ruleActions(policy)...) {
		if action.Type == "reverse_proxy" {
			needed[action.Upstream] = true
		}
	}
	seen := make(map[string]bool)
	for _, config := range upstreams {
		if config.ID == "" || seen[config.ID] {
			return nil, errors.New("duplicate or empty upstream ID")
		}
		seen[config.ID] = true
		if !needed[config.ID] {
			continue
		}
		u, err := compileUpstream(config)
		if err != nil {
			return nil, err
		}
		e.upstreams[config.ID] = u
	}
	for id := range needed {
		if e.upstreams[id] == nil {
			return nil, fmt.Errorf("upstream %s not found", id)
		}
	}
	return e, nil
}

func ruleActions(p *Policy) []contract.Action {
	out := make([]contract.Action, 0, len(p.rules))
	for _, r := range p.rules {
		out = append(out, r.rule.Action)
	}
	return out
}
func (e *Engine) Close() error {
	if e.healthCancel != nil {
		e.healthCancel()
		e.healthWG.Wait()
	}
	return e.pool.Close()
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	e.Counters.Requests.Add(1)
	defer func() { e.Counters.DurationNS.Add(uint64(time.Since(start))) }()
	if e.config.Debug {
		trace := newRequestTrace(e.config.ID, e.config.Name, w, r)
		w = trace.writer
		if trace.body != nil {
			r.Body = trace.body
		}
		defer trace.finish(start)
	}
	if r.Method == http.MethodConnect {
		http.Error(w, "nested CONNECT is unsupported", http.StatusMethodNotAllowed)
		return
	}
	if r.URL == nil || r.Host == "" || r.URL.User != nil || r.URL.Fragment != "" || (r.URL.Host != "" && !strings.EqualFold(r.URL.Host, r.Host)) {
		http.Error(w, "invalid HTTP authority", http.StatusBadRequest)
		return
	}
	meta, _ := r.Context().Value(metadataKey{}).(Metadata)
	base := r.Context()
	if meta.Context != nil {
		base = WithMetadata(netapi.ForkContext(meta.Context), meta)
		base = cancelWithRequest(base, r.Context())
	}
	ctx := netapi.ForkContext(base)
	// Keep only request-private state under netapi's context key.
	r = r.Clone(ctx)
	if r.URL.Scheme == "" {
		r.URL.Scheme = meta.Scheme
		if r.URL.Scheme == "" {
			r.URL.Scheme = "http"
			if r.TLS != nil {
				r.URL.Scheme = "https"
			}
		}
	}
	r.URL.Host = r.Host
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		http.Error(w, "unsupported URL scheme", 400)
		return
	}
	if e.access != nil {
		// The request authority may change on a reused intercepted connection.
		// Authorize it independently of routing and Gateway actions, including
		// local responses. Identity comes only from trusted ingress metadata.
		target := r.URL.Host
		if r.URL.Port() == "" {
			port := "80"
			if r.URL.Scheme == "https" {
				port = "443"
			}
			target = net.JoinHostPort(r.URL.Hostname(), port)
		}
		original, err := netapi.ParseAddress("tcp", target)
		if err != nil {
			http.Error(w, "invalid destination", http.StatusBadRequest)
			return
		}
		actual, err := netapi.PinTrafficDestination(ctx, e.access, original)
		if err != nil {
			e.Counters.Blocked.Add(1)
			e.auditLocal(ctx, r, true)
			http.Error(w, "traffic access denied", http.StatusForbidden)
			return
		}
		requestCtx, release, err := netapi.AuthorizeTrafficRequest(ctx, e.access, original, actual)
		if err != nil {
			e.Counters.Blocked.Add(1)
			e.auditLocal(ctx, r, true)
			http.Error(w, "traffic access denied", http.StatusForbidden)
			return
		}
		defer release()
		defer interruptRevokedResponse(requestCtx, w)()
		r = r.WithContext(requestCtx)
	}
	if e.config.MaxBodyBytes > 0 {
		if r.ContentLength > e.config.MaxBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, e.config.MaxBodyBytes)
	}
	result := e.policy.evaluate(r, ctx, false)
	a := result.Action
	if a.Type != "respond" && a.Type != "block" && e.filters.blocked(r) {
		a = contract.Action{Type: "block", Status: 204}
	}
	if result.RuleID != "" {
		ctx.SetMatchedRule(result.RuleID, "")
	}
	switch a.Type {
	case "block", "respond":
		e.auditLocal(ctx, r, a.Type == "block")
		if a.Type == "block" {
			e.Counters.Blocked.Add(1)
		}
		applyHeaders(w.Header(), a.ResponseHeaders)
		status := a.Status
		if status == 0 {
			status = 200
			if a.Type == "block" {
				status = 403
			}
		}
		w.WriteHeader(status)
		if r.Method != http.MethodHead && status != 204 && status != 304 {
			_, _ = w.Write([]byte(a.Body))
		}
		return
	case "redirect":
		e.auditLocal(ctx, r, false)
		applyHeaders(w.Header(), a.ResponseHeaders)
		if a.Location == r.URL.String() || a.Location == r.URL.RequestURI() {
			http.Error(w, "redirect loop", http.StatusLoopDetected)
			return
		}
		http.Redirect(w, r, a.Location, a.Status)
		return
	}
	var selectedUpstream *upstream
	var timeouts *proxyTimeout
	if a.Type == "reverse_proxy" {
		selectedUpstream = e.upstreams[a.Upstream]
	}
	if selectedUpstream != nil {
		release, err := selectedUpstream.acquire()
		if err != nil {
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
		defer release()
		if selectedUpstream.config.RequestTimeoutMS > 0 || selectedUpstream.config.StreamIdleMS > 0 {
			timeouts = newProxyTimeout(r.Context(), selectedUpstream.config.RequestTimeoutMS, selectedUpstream.config.StreamIdleMS)
			defer timeouts.close()
			r = r.WithContext(timeouts.ctx)
		}
	}
	var b *backend
	if selectedUpstream != nil {
		var err error
		b, err = selectedUpstream.pick()
		if err != nil {
			e.fail(w)
			return
		}
	}
	failed := false
	if b != nil {
		defer func() { selectedUpstream.finish(b, failed) }()
	}
	upstreamConfig := contract.Upstream{}
	if selectedUpstream != nil {
		upstreamConfig = selectedUpstream.config
	}
	target := a.Outbound
	if (target.Type == "" || target.Type == "inherit_route") && selectedUpstream != nil {
		target = upstreamConfig.Outbound
	}
	proxy := &httputil.ReverseProxy{
		BufferPool: pool.ReverseProxyBuffer{}, FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.RequestURI = ""
			if b != nil {
				pr.SetURL(b.url)
				if a.PreserveHost {
					pr.Out.Host = pr.In.Host
				}
			}
			applyRewrite(pr.Out, a.Rewrite)
			// Rewrite strips untrusted Forwarded/X-Forwarded headers before this
			// callback. Derive replacements only from the admitted connection.
			pr.SetXForwarded()
			pr.Out.Header.Del("Proxy-Authorization")
		},
		Transport: roundTripFunc(func(out *http.Request) (*http.Response, error) {
			address, err := requestDestination(out, meta, a, b != nil)
			if err != nil {
				return nil, err
			}
			if e.selectOutbound == nil {
				return nil, errors.New("outbound resolver unavailable")
			}
			s, err := e.selectOutbound(out.Context(), address, target)
			if err != nil {
				return nil, err
			}
			// A pooled upstream connection is observed with the identity of its
			// first dial. Keep authenticated ingress scopes separate so another
			// user, credential or client source cannot inherit that attribution.
			if identity := netapi.TrafficIdentity(out.Context()); identity != nil {
				nc := netapi.GetContext(out.Context())
				source := ""
				if nc.Source != nil {
					source = nc.Source.String()
				}
				s.TrafficScope = identity.CredentialID + "\x00" + nc.GetInboundID() + "\x00" + source
				// Membership/credential reload preserves the credential ID but
				// replaces its revoked immutable identity. Never retain a dial
				// closure bound to that retired identity in the new pool entry.
				s.TrafficGeneration = identity
			}
			label := s.Label
			if label == "" {
				label = s.Identity
			}
			e.lastOutbound.Store(new(label))
			tr, release, err := e.pool.borrow(s, out.URL.Scheme+"://"+out.URL.Host, upstreamConfig)
			if err != nil {
				return nil, err
			}
			// ReverseProxy completes body streaming before ServeHTTP returns.
			// Hold transport ownership through response EOF/Close (including upgrades).
			resp, err := roundTripWithRetry(tr, out, upstreamConfig.Retries)
			if err != nil {
				release()
				return nil, err
			}
			resp.Body = wrapResponseBody(resp.Body, release)
			if timeouts != nil && isStreamingResponse(resp) {
				resp.Body = timeouts.stream(resp.Body)
			}
			return resp, nil
		}),
		ModifyResponse: func(resp *http.Response) error {
			applyHeaders(resp.Header, a.ResponseHeaders)
			if resp.StatusCode >= 500 {
				failed = true
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			failed = true
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				e.Counters.Errors.Add(1)
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			e.fail(w)
		},
	}
	e.Counters.Forwarded.Add(1)
	proxy.ServeHTTP(w, r)
}

// requestContext preserves the immutable connection metadata but delegates
// cancellation and deadline to the individual HTTP stream.
type requestContext struct {
	context.Context
	request context.Context
}

func (c requestContext) Deadline() (time.Time, bool) { return c.request.Deadline() }
func (c requestContext) Done() <-chan struct{}       { return c.request.Done() }
func (c requestContext) Err() error                  { return c.request.Err() }
func cancelWithRequest(base, request context.Context) context.Context {
	return requestContext{base, request}
}

func requestDestination(r *http.Request, meta Metadata, a contract.Action, reverse bool) (netapi.Address, error) {
	if !reverse && a.Rewrite.Host == "" && a.Rewrite.Scheme == "" {
		if meta.OriginalDestination == nil {
			return nil, errors.New("forward requires an admitted original destination")
		}
		if meta.Authority != "" && hostname(r.Host) != hostname(meta.Authority) {
			return nil, errors.New("request authority differs from admitted destination")
		}
		return meta.OriginalDestination, nil
	}
	u := r.URL
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return netapi.ParseAddress("tcp", net.JoinHostPort(u.Hostname(), port))
}

func applyRewrite(r *http.Request, v contract.Rewrite) {
	if v.Scheme != "" {
		r.URL.Scheme = v.Scheme
	}
	if v.Host != "" {
		r.URL.Host = v.Host
		r.Host = v.Host
	}
	if v.Path != "" {
		r.URL.Path = v.Path
		r.URL.RawPath = ""
	}
	if v.Query != nil {
		r.URL.RawQuery = *v.Query
	}
	applyHeaders(r.Header, v.Headers)
}
func applyHeaders(dst, src http.Header) {
	for k, vs := range src {
		dst.Del(k)
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
func (e *Engine) fail(w http.ResponseWriter) {
	e.Counters.Errors.Add(1)
	http.Error(w, "gateway upstream unavailable", http.StatusBadGateway)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (e *Engine) Test(request contract.TestRequest) (contract.TestResult, error) {
	u, err := url.Parse(request.URL)
	if err != nil || u == nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return contract.TestResult{}, errors.New("test URL must be absolute HTTP or HTTPS")
	}
	method := request.Method
	if method == "" {
		method = http.MethodGet
	}
	r, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return contract.TestResult{}, err
	}
	r.Header = request.Headers
	ctx := netapi.WithContext(context.Background()).SetInboundID(request.InboundID).SetProcess(request.Process, 0, 0)
	result := e.policy.evaluate(r, ctx, true)
	if result.Action.Type != "respond" && result.Action.Type != "block" && e.filters.blocked(r) {
		result.Action = contract.Action{Type: "block", Status: http.StatusNoContent}
		result.Steps = append(result.Steps, contract.MatchStep{RuleID: "url-filters", Name: "URL filters", Matched: true})
		result.RuleID = "url-filters"
	}
	result.RequiresMITM = u.Scheme == "https"
	if upstream := e.upstreams[result.Action.Upstream]; result.Action.Type == "reverse_proxy" && upstream != nil && (result.Action.Outbound.Type == "" || result.Action.Outbound.Type == "inherit_route") {
		result.Action.Outbound = upstream.config.Outbound
	}
	return result, nil
}
