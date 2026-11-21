package netapi

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
)

// DNS history vocabulary. Values are stored and filtered verbatim, so they are
// part of the management API and must not be renamed.
const (
	DNSSourceLocal  = "local_dns"
	DNSSourceHijack = "dns_hijack"

	DNSResolutionLocal     = "local_response"
	DNSResolutionHosts     = "hosts"
	DNSResolutionCustom    = "custom_response"
	DNSResolutionFakeIP    = "fakeip"
	DNSResolutionCache     = "cache"
	DNSResolutionUpstream  = "upstream"
	DNSResolutionBlocked   = "blocked"
	DNSResolutionUnknown   = "unknown"
	DNSCacheHit            = "hit"
	DNSCacheMiss           = "miss"
	DNSCacheBypass         = "bypass"
	DNSCacheUnknown        = "unknown"
	DNSOutcomeSuccess      = "success"
	DNSOutcomeNXDomain     = "nxdomain"
	DNSOutcomeNoData       = "nodata"
	DNSOutcomeServFail     = "servfail"
	DNSOutcomeRefused      = "refused"
	DNSOutcomeOtherRcode   = "other_rcode"
	DNSOutcomeTimeout      = "timeout"
	DNSOutcomeCanceled     = "canceled"
	DNSOutcomeRejected     = "rejected"
	DNSOutcomeDropped      = "dropped"
	DNSOutcomeMalformed    = "malformed"
	DNSOutcomeWriteError   = "write_error"
	DNSOutcomeInternal     = "internal_error"
	DNSStageIngress        = "ingress"
	DNSStageAuthorization  = "authorization"
	DNSStageTrafficControl = "traffic_control"
	DNSStageAdmission      = "dns_admission"
	DNSStageResolver       = "resolver"
	DNSStageUpstream       = "upstream"
	DNSStagePack           = "response_pack"
	DNSStageDelivery       = "response_delivery"
)

// DNSObserver starts the history trace of one client DNS request. It returns
// nil when observation is disabled; every DNSTrace method accepts nil, so the
// disabled path costs one call and no allocation.
type DNSObserver interface {
	BeginDNS(transport, sourceType string) *DNSTrace
}

// DNSRecordSnapshot keeps the records of a response section without copying
// them. Resolvers never mutate records after publishing a message (cached
// messages are shared read-only), so formatting can wait for the history
// worker and stays off the DNS path.
type DNSResponseSnapshot struct {
	Answer, Authority, Additional []dns.RR
	Rcode                         uint16
	Authoritative                 bool
	Truncated                     bool
	RecursionDesired              bool
	RecursionAvailable            bool
	AuthenticatedData             bool
	CheckingDisabled              bool
}

// DNSAttempt is one upstream exchange really performed for this request.
type DNSAttempt struct {
	Resolver  string        `json:"resolver"`
	Server    string        `json:"server,omitempty"`
	Transport string        `json:"transport,omitempty"`
	Offset    time.Duration `json:"offsetNs"`
	Duration  time.Duration `json:"durationNs"`
	Result    string        `json:"result"`
	Rcode     string        `json:"rcode,omitempty"`
	Error     string        `json:"error,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
}

// DNSTraceData is the completed observation handed to the history sink. It
// holds no packet, connection or request context.
type DNSTraceData struct {
	CreatedAt time.Time
	Duration  time.Duration

	Transport  string
	SourceType string
	ClientIP   string
	ClientPort uint16

	InboundID    string
	InboundName  string
	ProcessName  string
	PID          uint
	UID          uint
	UserID       string
	CredentialID string
	GroupIDs     []string

	TransactionID  uint16
	Domain         string
	QType          uint16
	QClass         uint16
	RequestSize    int
	RequestRD      bool
	RequestCD      bool
	RequestAD      bool
	RequestDO      bool
	RequestUDPSize uint16

	Admission   string
	QueueWait   time.Duration
	ForceFakeIP bool

	Resolver        string
	ResolverLabel   string
	Server          string
	ServerType      string
	ServerTransport string
	RouteMode       string
	RouteRuleID     string
	RouteRuleName   string
	SelectionReason string
	CacheStatus     string
	CacheStale      bool
	SharedQuery     bool
	Source          string
	HostsRewrite    string

	FakeIPRequested  bool
	FakeIPReturned   bool
	FakeIPGlobal     bool
	FakeIPSkipCheck  bool
	FakeIPv4         string
	FakeIPv6         string
	FakeIPPoolIPv4   string
	FakeIPPoolIPv6   string
	FakeIPReason     string
	FakeIPAllocation string
	FakeIPError      string

	Outcome       string
	FailureStage  string
	FailureReason string
	Error         string

	Response       *DNSResponseSnapshot
	ResponseSize   int
	SentBytes      int
	ServerTruncate bool

	Attempts []DNSAttempt
}

const maxDNSAttempts = 8

// DNSTrace accumulates one request's observation. Resolver layers update it
// through the request context; it is safe for concurrent use because a lookup
// may fan out to goroutines. Updates after Finish, from nested lookups made
// while matching routes, or for a different question are ignored.
type DNSTrace struct {
	mu       sync.Mutex
	data     DNSTraceData
	started  time.Time
	nested   int
	store    *Context
	finished atomic.Bool
	sink     func(*DNSTraceData)
}

func NewDNSTrace(transport, sourceType string, sink func(*DNSTraceData)) *DNSTrace {
	now := time.Now()
	return &DNSTrace{started: now, sink: sink, data: DNSTraceData{CreatedAt: now, Transport: transport, SourceType: sourceType}}
}

type dnsTraceKey struct{}

// WithDNSTrace attaches t; a nil t detaches any trace inherited from ctx.
func WithDNSTrace(ctx context.Context, t *DNSTrace) context.Context {
	if t == nil && DNSTraceFromContext(ctx) == nil {
		return ctx
	}
	return context.WithValue(ctx, dnsTraceKey{}, t)
}

// WithoutDNSTrace is used by work that outlives or is unrelated to the client
// request, such as background cache refreshes and upstream dials.
func WithoutDNSTrace(ctx context.Context) context.Context { return WithDNSTrace(ctx, nil) }

func DNSTraceFromContext(ctx context.Context) *DNSTrace {
	if ctx == nil {
		return nil
	}
	t, _ := ctx.Value(dnsTraceKey{}).(*DNSTrace)
	return t
}

func (t *DNSTrace) update(f func(*DNSTraceData)) {
	if t == nil || t.finished.Load() {
		return
	}
	t.mu.Lock()
	if !t.finished.Load() && t.nested == 0 {
		f(&t.data)
	}
	t.mu.Unlock()
}

// Nest suspends recording while a route decision performs ancillary lookups
// (GeoIP, IP-CIDR rules) with the same context. The returned func resumes it.
func (t *DNSTrace) Nest() func() {
	if t == nil {
		return func() {}
	}
	t.mu.Lock()
	t.nested++
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		t.nested--
		t.mu.Unlock()
	}
}

// BindContext lets Finish read process details already discovered for this
// request (for example by process route rules). DNS never forces a lookup.
func (t *DNSTrace) BindContext(store *Context) {
	t.update(func(*DNSTraceData) { t.store = store })
}

func (t *DNSTrace) SetClient(addr net.Addr) {
	if t == nil || addr == nil {
		return
	}
	ap := addrPortOf(addr)
	t.update(func(d *DNSTraceData) {
		if ap.IsValid() {
			d.ClientIP, d.ClientPort = ap.Addr().Unmap().String(), ap.Port()
		} else {
			d.ClientIP = addr.String()
		}
	})
}

func addrPortOf(addr net.Addr) netip.AddrPort {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.AddrPort()
	case *net.TCPAddr:
		return a.AddrPort()
	case IPAddress:
		return a.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(addr.String())
	return ap
}

func (t *DNSTrace) SetInbound(id, name string) {
	t.update(func(d *DNSTraceData) { d.InboundID, d.InboundName = id, name })
}

func (t *DNSTrace) SetIdentity(userID, credentialID string, groups []string) {
	t.update(func(d *DNSTraceData) {
		d.UserID, d.CredentialID = userID, credentialID
		d.GroupIDs = append([]string(nil), groups...)
	})
}

func (t *DNSTrace) SetForceFakeIP(force bool) {
	t.update(func(d *DNSTraceData) { d.ForceFakeIP = force })
}

// SetQuery records the client's request header and question.
func (t *DNSTrace) SetQuery(msg *dns.Msg, size int) {
	if t == nil || msg == nil {
		return
	}
	t.update(func(d *DNSTraceData) {
		d.TransactionID, d.RequestSize = msg.ID, size
		d.RequestRD, d.RequestCD, d.RequestAD = msg.RecursionDesired, msg.CheckingDisabled, msg.AuthenticatedData
		d.RequestDO, d.RequestUDPSize = msg.Security, msg.UDPSize
		if len(msg.Question) > 0 {
			q := DNSQuestionFromRR(msg.Question[0])
			d.Domain, d.QType, d.QClass = q.Name, q.Qtype, q.Qclass
		}
	})
}

// SetRequestWire parses the request only for a request rejected before the
// DNS server parsed it. A malformed packet keeps its size and no question.
func (t *DNSTrace) SetRequestWire(b []byte) {
	if t == nil {
		return
	}
	msg := &dns.Msg{Data: b}
	if err := msg.Unpack(); err != nil {
		t.update(func(d *DNSTraceData) { d.RequestSize = len(b) })
		return
	}
	t.SetQuery(msg, len(b))
}

func (t *DNSTrace) SetAdmission(result string) {
	t.update(func(d *DNSTraceData) { d.Admission = result })
}

func (t *DNSTrace) SetQueueWait(wait time.Duration) {
	t.update(func(d *DNSTraceData) { d.QueueWait = wait })
}

// SetSource records which layer produced the answer. Later layers override
// earlier ones: FakeIP rewrites an upstream answer after querying it.
func (t *DNSTrace) SetSource(source string) {
	t.update(func(d *DNSTraceData) { d.Source = source })
}

func (t *DNSTrace) SetHostsRewrite(name string) {
	t.update(func(d *DNSTraceData) { d.HostsRewrite = name })
}

// SetRoute records the route decision that selected the resolver.
func (t *DNSTrace) SetRoute(mode, resolver, ruleID, ruleName, reason string) {
	t.update(func(d *DNSTraceData) {
		d.RouteMode, d.Resolver, d.RouteRuleID, d.RouteRuleName, d.SelectionReason = mode, resolver, ruleID, ruleName, reason
	})
}

// DNSServerInfo describes the upstream resolver that served the question.
type DNSServerInfo struct {
	Resolver, Label, Server, Type string
}

func (t *DNSTrace) matches(d *DNSTraceData, q DNSQuestion) bool {
	if d.Domain == "" {
		return true
	}
	name := d.Domain
	if d.HostsRewrite != "" {
		name = d.HostsRewrite
	}
	return q.Qtype == d.QType && strings.EqualFold(strings.TrimSuffix(q.Name, "."), strings.TrimSuffix(name, "."))
}

func (d *DNSTraceData) setServer(info DNSServerInfo) {
	d.Resolver, d.ResolverLabel, d.Server, d.ServerType = info.Resolver, info.Label, info.Server, info.Type
}

// RecordCache records a resolver cache lookup for the request's question.
func (t *DNSTrace) RecordCache(q DNSQuestion, info DNSServerInfo, hit, stale bool) {
	t.update(func(d *DNSTraceData) {
		if !t.matches(d, q) {
			return
		}
		d.setServer(info)
		if hit {
			d.CacheStatus, d.CacheStale, d.Source = DNSCacheHit, stale, DNSResolutionCache
		} else {
			d.CacheStatus = DNSCacheMiss
		}
	})
}

// RecordShared marks that the answer came from an upstream exchange that
// another request started (singleflight); its attempts belong to that request.
func (t *DNSTrace) RecordShared(q DNSQuestion, info DNSServerInfo) {
	t.update(func(d *DNSTraceData) {
		if t.matches(d, q) {
			d.setServer(info)
			d.SharedQuery, d.CacheStatus, d.Source = true, DNSCacheMiss, DNSResolutionUpstream
		}
	})
}

// RecordAttempt appends an upstream exchange performed by this request.
func (t *DNSTrace) RecordAttempt(q DNSQuestion, info DNSServerInfo, transport string, started time.Time, err error, msg *dns.Msg) {
	if t == nil {
		return
	}
	elapsed := time.Since(started)
	t.update(func(d *DNSTraceData) {
		if !t.matches(d, q) {
			return
		}
		d.setServer(info)
		d.ServerTransport, d.CacheStatus, d.Source = transport, DNSCacheMiss, DNSResolutionUpstream
		if len(d.Attempts) >= maxDNSAttempts {
			return
		}
		a := DNSAttempt{Resolver: info.Label, Server: info.Server, Transport: transport, Offset: started.Sub(t.started), Duration: elapsed, Result: "success"}
		if a.Resolver == "" {
			a.Resolver = info.Resolver
		}
		switch {
		case err != nil:
			a.Result, a.Error = ClassifyDNSError(err), truncateString(err.Error(), 256)
		case msg != nil:
			a.Rcode, a.Truncated = dns.RcodeToString[msg.Rcode], msg.Truncated
			if msg.Truncated {
				a.Result = "truncated"
			}
		}
		d.Attempts = append(d.Attempts, a)
	})
}

// FakeIPDecision records why the FakeIP layer did or did not try to answer.
func (t *DNSTrace) FakeIPDecision(requested, global, force, skipCheck bool, reason string) {
	t.update(func(d *DNSTraceData) {
		d.FakeIPRequested, d.FakeIPGlobal, d.FakeIPSkipCheck, d.FakeIPReason = requested, global, skipCheck, reason
		d.ForceFakeIP = d.ForceFakeIP || force
	})
}

// FakeIPResult records the FakeIP pool's actual result. ip is invalid when no
// synthetic address was returned.
func (t *DNSTrace) FakeIPResult(status string, ipv4, ipv6 netip.Addr, pool4, pool6 netip.Prefix, err error) {
	t.update(func(d *DNSTraceData) {
		d.FakeIPAllocation = status
		d.FakeIPPoolIPv4, d.FakeIPPoolIPv6 = prefixString(pool4), prefixString(pool6)
		if ipv4.IsValid() {
			d.FakeIPv4 = ipv4.String()
		}
		if ipv6.IsValid() {
			d.FakeIPv6 = ipv6.String()
		}
		d.FakeIPReturned = ipv4.IsValid() || ipv6.IsValid()
		if d.FakeIPReturned {
			d.Source = DNSResolutionFakeIP
		}
		if err != nil {
			d.FakeIPError = truncateString(err.Error(), 256)
		}
	})
}

func prefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

// Fail classifies a failure at the stage where it happened. The first
// classification wins: a later generic error cannot hide the real cause.
func (t *DNSTrace) Fail(outcome, stage, reason string, err error) {
	t.update(func(d *DNSTraceData) {
		if d.Outcome != "" {
			return
		}
		d.Outcome, d.FailureStage, d.FailureReason = outcome, stage, reason
		if err != nil {
			d.Error = truncateString(err.Error(), 512)
		}
	})
}

// SetResponse records the response produced for the client before delivery.
func (t *DNSTrace) SetResponse(msg *dns.Msg) {
	if t == nil || msg == nil {
		return
	}
	snapshot := &DNSResponseSnapshot{
		Answer: msg.Answer, Authority: msg.Ns, Additional: msg.Extra, Rcode: msg.Rcode,
		Authoritative: msg.Authoritative, Truncated: msg.Truncated, RecursionDesired: msg.RecursionDesired,
		RecursionAvailable: msg.RecursionAvailable, AuthenticatedData: msg.AuthenticatedData, CheckingDisabled: msg.CheckingDisabled,
	}
	t.update(func(d *DNSTraceData) { d.Response = snapshot })
}

// SetDelivery records the packed response size, whether the server truncated
// it to the client's UDP limit, and the bytes the transport reported sent.
func (t *DNSTrace) SetDelivery(size int, serverTruncated bool) {
	t.update(func(d *DNSTraceData) {
		d.ResponseSize, d.ServerTruncate = size, serverTruncated
		if d.Response != nil && serverTruncated {
			d.Response.Truncated = true
		}
	})
}

func (t *DNSTrace) AddSent(n int) {
	if n > 0 {
		t.update(func(d *DNSTraceData) { d.SentBytes += n })
	}
}

// Finish completes the request exactly once. err is the request's final
// error, nil when a response was delivered. The trace must not be used
// afterwards; the sink owns the data.
func (t *DNSTrace) Finish(err error) {
	if t == nil || !t.finished.CompareAndSwap(false, true) {
		return
	}
	t.mu.Lock()
	d := t.data
	store := t.store
	t.store = nil
	t.mu.Unlock()
	if store != nil {
		d.ProcessName, d.PID, d.UID = store.GetProcess()
	}
	d.Duration = time.Since(t.started)
	finalizeDNSTrace(&d, err)
	if t.sink != nil {
		t.sink(&d)
	}
}

func finalizeDNSTrace(d *DNSTraceData, err error) {
	if d.Outcome == "" && err != nil {
		outcome := ClassifyDNSError(err)
		stage := DNSStageResolver
		if len(d.Attempts) > 0 {
			stage = DNSStageUpstream
		}
		d.Outcome, d.FailureStage, d.FailureReason = outcome, stage, outcome
		d.Error = truncateString(err.Error(), 512)
	}
	if d.Outcome == "" {
		switch {
		case d.Response == nil:
			d.Outcome, d.FailureStage, d.FailureReason = DNSOutcomeInternal, DNSStageResolver, "no_response"
		case d.SentBytes < d.ResponseSize:
			d.Outcome, d.FailureStage, d.FailureReason = DNSOutcomeWriteError, DNSStageDelivery, "partial_write"
		default:
			d.Outcome = DNSOutcomeFromResponse(d.Response, d.QType)
		}
	}
	if d.Source == "" {
		if d.Response != nil {
			d.Source = DNSResolutionUnknown
		}
	}
	if d.CacheStatus == "" {
		switch d.Source {
		case DNSResolutionCustom, DNSResolutionHosts, DNSResolutionFakeIP, DNSResolutionLocal, DNSResolutionBlocked:
			d.CacheStatus = DNSCacheBypass
		default:
			d.CacheStatus = DNSCacheUnknown
		}
	}
	if d.FakeIPReason == "" {
		d.FakeIPReason = "not_applicable"
	}
	if d.FakeIPAllocation == "" {
		d.FakeIPAllocation = "not_requested"
	}
}

// DNSOutcomeFromResponse separates the protocol result from internal errors:
// NXDOMAIN is a valid answer, and NODATA is NOERROR without the asked type.
func DNSOutcomeFromResponse(r *DNSResponseSnapshot, qtype uint16) string {
	switch r.Rcode {
	case dns.RcodeSuccess:
		for _, rr := range r.Answer {
			if t := dns.RRToType(rr); t == qtype || qtype == dns.TypeANY {
				return DNSOutcomeSuccess
			}
		}
		return DNSOutcomeNoData
	case dns.RcodeNameError:
		return DNSOutcomeNXDomain
	case dns.RcodeServerFailure:
		return DNSOutcomeServFail
	case dns.RcodeRefused:
		return DNSOutcomeRefused
	default:
		return DNSOutcomeOtherRcode
	}
}

// ClassifyDNSError maps an error to an outcome without string matching where
// a typed error exists.
func ClassifyDNSError(err error) string {
	switch {
	case err == nil:
		return DNSOutcomeSuccess
	case errors.Is(err, context.DeadlineExceeded):
		return DNSOutcomeTimeout
	case errors.Is(err, context.Canceled):
		return DNSOutcomeCanceled
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return DNSOutcomeTimeout
	}
	return DNSOutcomeInternal
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}
