// Package dnshistory defines the management API of the DNS query history.
//
// A record describes one client DNS request from receipt to delivery. The
// protocol result (Rcode) and the request outcome are independent: NXDOMAIN
// is a successfully delivered answer, while a timeout has no Rcode at all.
package dnshistory

// Record is one client DNS request. Fields that the server could not observe
// are empty or "unknown"; they are never guessed from configuration.
type Record struct {
	ID         int64  `json:"id"`
	CreatedAt  string `json:"createdAt"`
	DurationNs int64  `json:"durationNs"`
	Transport  string `json:"transport"`
	SourceType string `json:"sourceType"`
	ClientIP   string `json:"clientIp,omitempty"`
	ClientPort int    `json:"clientPort,omitempty"`

	InboundID    string   `json:"inboundId,omitempty"`
	InboundName  string   `json:"inboundName,omitempty"`
	ProcessName  string   `json:"processName,omitempty"`
	PID          int64    `json:"pid,omitempty"`
	UID          int64    `json:"uid,omitempty"`
	UserID       string   `json:"userId,omitempty"`
	CredentialID string   `json:"credentialId,omitempty"`
	GroupIDs     []string `json:"groupIds,omitempty"`

	Domain        string `json:"domain"`
	QueryType     string `json:"queryType"`
	QueryClass    string `json:"queryClass"`
	TransactionID int    `json:"transactionId"`

	Resolver         string `json:"resolver,omitempty"`
	ResolverLabel    string `json:"resolverLabel,omitempty"`
	Server           string `json:"server,omitempty"`
	ServerType       string `json:"serverType,omitempty"`
	RouteMode        string `json:"routeMode,omitempty"`
	RouteRuleID      string `json:"routeRuleId,omitempty"`
	RouteRuleName    string `json:"routeRuleName,omitempty"`
	CacheStatus      string `json:"cacheStatus"`
	ResolutionSource string `json:"resolutionSource"`

	FakeIP FakeIP `json:"fakeip"`

	Outcome       string `json:"outcome"`
	Rcode         string `json:"rcode,omitempty"`
	FailureStage  string `json:"failureStage,omitempty"`
	FailureReason string `json:"failureReason,omitempty"`
	Error         string `json:"error,omitempty"`

	RequestSize     int    `json:"requestSize"`
	ResponseSize    int    `json:"responseSize"`
	SentBytes       int    `json:"sentBytes"`
	AnswerCount     int    `json:"answerCount"`
	AuthorityCount  int    `json:"authorityCount"`
	AdditionalCount int    `json:"additionalCount"`
	AnswerSummary   string `json:"answerSummary,omitempty"`

	// Detail fields are returned by dns.history.get only.
	Answer     []ResourceRecord `json:"answer,omitempty"`
	Authority  []ResourceRecord `json:"authority,omitempty"`
	Additional []ResourceRecord `json:"additional,omitempty"`
	Flags      *ResponseFlags   `json:"flags,omitempty"`
	Details    *Details         `json:"details,omitempty"`
}

type FakeIP struct {
	Requested  bool   `json:"requested"`
	Returned   bool   `json:"returned"`
	IPv4       string `json:"ipv4,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
	PoolIPv4   string `json:"poolIpv4,omitempty"`
	PoolIPv6   string `json:"poolIpv6,omitempty"`
	Reason     string `json:"reason"`
	Allocation string `json:"allocation"`
	Error      string `json:"error,omitempty"`
	// Force and Global show the two inputs; Reason states which one applied.
	Force     bool `json:"force"`
	Global    bool `json:"global"`
	SkipCheck bool `json:"skipCheck"`
}

// ResourceRecord is a generic RR in presentation format, so every type
// (CNAME, MX, TXT, SRV, HTTPS, SVCB, PTR ...) is shown without a special case.
type ResourceRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
	// DataTruncated marks RDATA shortened to the storage limit.
	DataTruncated bool `json:"dataTruncated,omitempty"`
}

type ResponseFlags struct {
	AA bool `json:"aa"`
	TC bool `json:"tc"`
	RD bool `json:"rd"`
	RA bool `json:"ra"`
	AD bool `json:"ad"`
	CD bool `json:"cd"`
	// ServerTruncated means the response exceeded the client's UDP size and
	// was sent with TC set and without records; the stored records are the
	// resolved ones.
	ServerTruncated bool `json:"serverTruncated"`
	// Omitted counts records beyond the per-section storage limit.
	AnswerOmitted     int `json:"answerOmitted,omitempty"`
	AuthorityOmitted  int `json:"authorityOmitted,omitempty"`
	AdditionalOmitted int `json:"additionalOmitted,omitempty"`
}

// Details holds diagnostics that are displayed but not filtered on.
type Details struct {
	Admission       string    `json:"admission,omitempty"`
	QueueWaitNs     int64     `json:"queueWaitNs,omitempty"`
	SelectionReason string    `json:"selectionReason,omitempty"`
	ServerTransport string    `json:"serverTransport,omitempty"`
	CacheStale      bool      `json:"cacheStale,omitempty"`
	SharedQuery     bool      `json:"sharedQuery,omitempty"`
	HostsRewrite    string    `json:"hostsRewrite,omitempty"`
	RequestRD       bool      `json:"requestRd"`
	RequestCD       bool      `json:"requestCd"`
	RequestAD       bool      `json:"requestAd"`
	RequestDO       bool      `json:"requestDo"`
	RequestUDPSize  int       `json:"requestUdpSize,omitempty"`
	Attempts        []Attempt `json:"attempts,omitempty"`
}

// Attempt is one upstream exchange this request actually performed.
type Attempt struct {
	Resolver   string `json:"resolver"`
	Server     string `json:"server,omitempty"`
	Transport  string `json:"transport,omitempty"`
	OffsetNs   int64  `json:"offsetNs"`
	DurationNs int64  `json:"durationNs"`
	Result     string `json:"result"`
	Rcode      string `json:"rcode,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ListRequest filters are combined with AND. Times are Unix milliseconds.
type ListRequest struct {
	// Page (1-based) selects a numbered page; Cursor continues after a
	// previous page instead. A caller keeps To fixed while paging so new
	// requests do not shift the pages.
	Page   int    `json:"page,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	// SortBy is time (default), domain, type, result or latency; SortOrder is
	// desc (default) or asc. A cursor only continues the newest-first order.
	SortBy    string `json:"sortBy,omitempty"`
	SortOrder string `json:"sortOrder,omitempty"`
	// Domain matches the name and its subdomains; Query is a substring of the
	// domain, process or client address.
	Domain     string `json:"domain,omitempty"`
	Query      string `json:"query,omitempty"`
	QueryType  string `json:"queryType,omitempty"`
	Transport  string `json:"transport,omitempty"`
	SourceType string `json:"sourceType,omitempty"`
	InboundID  string `json:"inboundId,omitempty"`
	Process    string `json:"process,omitempty"`
	Resolver   string `json:"resolver,omitempty"`
	Server     string `json:"server,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	Rcode      string `json:"rcode,omitempty"`
	FakeIPOnly bool   `json:"fakeipOnly,omitempty"`
	From       int64  `json:"from,omitempty"`
	To         int64  `json:"to,omitempty"`
}

type ListResponse struct {
	Items []Record `json:"items"`
	// NextCursor continues after the last item; empty on the last page.
	NextCursor string `json:"nextCursor,omitempty"`
	Total      int    `json:"total"`
	Page       int    `json:"page"`
	Limit      int    `json:"limit"`
}

type GetRequest struct {
	ID int64 `json:"id"`
}

type StatsRequest struct {
	From int64 `json:"from,omitempty"`
	To   int64 `json:"to,omitempty"`
}

type Stats struct {
	From         int64   `json:"from"`
	To           int64   `json:"to"`
	Total        int     `json:"total"`
	Success      int     `json:"success"`
	Failed       int     `json:"failed"`
	Dropped      int     `json:"dropped"`
	Timeout      int     `json:"timeout"`
	WriteErrors  int     `json:"writeErrors"`
	FakeIP       int     `json:"fakeip"`
	CacheHits    int     `json:"cacheHits"`
	CacheMisses  int     `json:"cacheMisses"`
	AvgLatencyNs float64 `json:"avgLatencyNs"`
	// Recorder state since process start.
	Recorder RecorderStatus `json:"recorder"`
}

// RecorderStatus separates lost history from lost DNS requests: a full
// history queue drops the record, never the request.
type RecorderStatus struct {
	Enabled              bool   `json:"enabled"`
	QueueLength          int    `json:"queueLength"`
	QueueCapacity        int    `json:"queueCapacity"`
	Persisted            uint64 `json:"persisted"`
	RecordsDropped       uint64 `json:"recordsDropped"`
	PersistenceErrors    uint64 `json:"persistenceErrors"`
	LastPersistenceError string `json:"lastPersistenceError,omitempty"`
	StartedAt            string `json:"startedAt"`
}

// Settings controls recording. Values outside the documented bounds are
// rejected.
type Settings struct {
	Enabled        bool `json:"enabled"`
	RetentionHours int  `json:"retentionHours"`
	MaxRecords     int  `json:"maxRecords"`
}

type ClearResponse struct {
	Deleted int `json:"deleted"`
}
