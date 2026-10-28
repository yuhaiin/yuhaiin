// Package gateway defines the persisted HTTP gateway and management API contract.
package gateway

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

// Config is replaced as one revision so references and activation stay atomic.
type Config struct {
	Revision      uint64         `json:"revision"`
	Gateways      []Gateway      `json:"gateways"`
	Rules         []Rule         `json:"rules"`
	Upstreams     []Upstream     `json:"upstreams"`
	Interceptions []Interception `json:"interceptions"`
	FilterLists   []FilterList   `json:"filterLists"`
}

type Gateway struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Debug    bool   `json:"debug"`
	Revision uint64 `json:"revision"`
	// Empty listen means interception only. Non-loopback listeners require an ACL.
	Listen                string   `json:"listen"`
	AllowedSources        []string `json:"allowedSources"`
	TLSMode               string   `json:"tlsMode"`
	CertificateFile       string   `json:"certificateFile"`
	KeyFile               string   `json:"keyFile"`
	ManagedCertificateIDs []string `json:"managedCertificateIds,omitempty"`
	ACMEHTTP01            bool     `json:"acmeHttp01,omitzero"`
	RuleIDs               []string `json:"ruleIds"`
	Default               Action   `json:"default"`
	MaxBodyBytes          int64    `json:"maxBodyBytes"`
}

type Rule struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Enabled  bool      `json:"enabled"`
	Priority int       `json:"priority"`
	Revision uint64    `json:"revision"`
	Match    Condition `json:"match"`
	Action   Action    `json:"action"`
}

// Condition is either a boolean expression or a leaf. No implicit mixed operators.
type Condition struct {
	All      []Condition `json:"all,omitempty"`
	Any      []Condition `json:"any,omitempty"`
	Not      *Condition  `json:"not,omitzero"`
	Field    string      `json:"field,omitempty"`
	Operator string      `json:"operator,omitempty"`
	Key      string      `json:"key,omitempty"`
	Values   []string    `json:"values,omitempty"`
	Value    string      `json:"value,omitempty"` // Legacy input; migrated when loading.
}

type Action struct {
	Type            string              `json:"type"`
	Upstream        string              `json:"upstream,omitempty"`
	Outbound        route.Target        `json:"outbound"`
	Status          int                 `json:"status,omitzero"`
	Body            string              `json:"body,omitempty"`
	Location        string              `json:"location,omitempty"`
	PreserveHost    bool                `json:"preserveHost"`
	Rewrite         Rewrite             `json:"rewrite"`
	ResponseHeaders map[string][]string `json:"responseHeaders,omitempty"`
}

type Rewrite struct {
	Scheme  string              `json:"scheme,omitempty"`
	Host    string              `json:"host,omitempty"`
	Path    string              `json:"path,omitempty"`
	Query   *string             `json:"query,omitzero"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type Upstream struct {
	ID                string       `json:"id"`
	Name              string       `json:"name"`
	Revision          uint64       `json:"revision"`
	Backends          []Backend    `json:"backends"`
	Balance           string       `json:"balance"`
	Outbound          route.Target `json:"outbound"`
	ServerName        string       `json:"serverName,omitempty"`
	TrustPEM          string       `json:"trustPem,omitempty"`
	ConnectTimeoutMS  int          `json:"connectTimeoutMs"`
	IdleTimeoutMS     int          `json:"idleTimeoutMs"`
	RequestTimeoutMS  int          `json:"requestTimeoutMs"`
	StreamIdleMS      int          `json:"streamIdleTimeoutMs"`
	MaxConnections    int          `json:"maxConnections"`
	MaxConcurrent     int          `json:"maxConcurrent"`
	RequestsPerSecond float64      `json:"requestsPerSecond"`
	Burst             int          `json:"burst"`
	HealthPath        string       `json:"healthPath,omitempty"`
	HealthIntervalMS  int          `json:"healthIntervalMs"`
	FailureThreshold  int          `json:"failureThreshold"`
	RecoveryMS        int          `json:"recoveryMs"`
	Retries           int          `json:"retries"`
}

type Backend struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

type Interception struct {
	GatewayID      string   `json:"gatewayId"`
	Mode           string   `json:"mode"`
	Domains        []string `json:"domains"`
	ExcludeDomains []string `json:"excludeDomains"`
	Ports          []uint16 `json:"ports"`
	Sources        []string `json:"sources"`
	Processes      []string `json:"processes"`
	// Unknown TLS (such as malformed ClientHello or unsupported ALPN) is passed
	// through or rejected before MITM begins. ECH offers use the visible outer
	// ClientHello when no ECH keys are configured. Empty is passthrough.
	UnknownTLS string `json:"unknownTls"`
}

type FilterList struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	GatewayID string    `json:"gatewayId"`
	Revision  uint64    `json:"revision"`
	URL       string    `json:"url,omitempty"`
	Text      string    `json:"text"`
	UpdatedAt time.Time `json:"updatedAt,omitzero"`
}

type TestRequest struct {
	GatewayID string              `json:"gatewayId"`
	URL       string              `json:"url"`
	Method    string              `json:"method"`
	InboundID string              `json:"inboundId"`
	Process   string              `json:"process,omitempty"`
	SourceIP  string              `json:"sourceIp,omitempty"`
	Headers   map[string][]string `json:"headers"`
}

type MatchStep struct {
	RuleID  string `json:"ruleId"`
	Name    string `json:"name"`
	Matched bool   `json:"matched"`
}

type TestResult struct {
	RuleID       string      `json:"ruleId"`
	Steps        []MatchStep `json:"steps"`
	Action       Action      `json:"action"`
	RequiresMITM bool        `json:"requiresMitm"`
}

type CAStatus struct {
	Present            bool      `json:"present"`
	Subject            string    `json:"subject"`
	Fingerprint        string    `json:"fingerprint"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	CertificatePEM     string    `json:"certificatePem"`
	CachedCertificates int       `json:"cachedCertificates"`
	CacheCapacity      int       `json:"cacheCapacity"`
	Revision           uint64    `json:"revision"`
}

// CAImport is write-only. PrivateKeyPEM must never occur in a response or log.
type CAImport struct {
	CertificatePEM string `json:"certificatePem"`
	PrivateKeyPEM  string `json:"privateKeyPem"`
	Revision       uint64 `json:"revision"`
}

// StatisticsTotals are persisted per Gateway, independent of live health gauges.
type StatisticsTotals struct {
	Requests         uint64
	Blocked          uint64
	Forwarded        uint64
	Errors           uint64
	TLSFailures      uint64
	ProtocolFailures uint64
	DurationNS       uint64
}

type RuntimeStatus struct {
	Revision     uint64          `json:"revision"`
	Gateways     []GatewayStatus `json:"gateways"`
	StartupError string          `json:"startupError,omitzero"`
}
type GatewayStatus struct {
	FilterReports    []FilterReport   `json:"filterReports"`
	ID               string           `json:"id"`
	Enabled          bool             `json:"enabled"`
	Requests         uint64           `json:"requests"`
	Blocked          uint64           `json:"blocked"`
	Forwarded        uint64           `json:"forwarded"`
	Errors           uint64           `json:"errors"`
	TLSFailures      uint64           `json:"tlsFailures"`
	ProtocolFailures uint64           `json:"protocolFailures"`
	DurationNS       uint64           `json:"durationNs"`
	LastOutbound     string           `json:"lastOutbound"`
	Upstreams        []UpstreamStatus `json:"upstreams"`
}
type UpstreamStatus struct {
	ID             string          `json:"id"`
	ActiveRequests int64           `json:"activeRequests"`
	Backends       []BackendStatus `json:"backends"`
}
type BackendStatus struct {
	URL            string `json:"url"`
	Healthy        bool   `json:"healthy"`
	ActiveRequests int64  `json:"activeRequests"`
	Failures       int64  `json:"failures"`
}

type FilterReport struct {
	ID       string   `json:"id"`
	Accepted int      `json:"accepted"`
	Rejected int      `json:"rejected"`
	Errors   []string `json:"errors"`
}
