package tools

// DiagnosticRequest selects a hostname, not a URL or a node configuration.
type DiagnosticRequest struct {
	Host string `json:"host"`
	TCPOnly bool `json:"tcpOnly,omitempty"`
}

type DiagnosticCheck struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`  // pass, fail, warning, skipped
	Message    string   `json:"message"` // stable code for client translations
	DurationMS int64    `json:"durationMs"`
	Evidence   []string `json:"evidence"`
}

type DiagnosticReport struct {
	SchemaVersion int               `json:"schemaVersion"`
	StartedAt     string            `json:"startedAt"`
	DurationMS    int64             `json:"durationMs"`
	Host          string            `json:"host"`
	Platform      string            `json:"platform"`
	Version       string            `json:"version"`
	IPv6Enabled   bool              `json:"ipv6Enabled"`
	Checks        []DiagnosticCheck `json:"checks"`
	Findings      []string          `json:"findings"` // evidence-based guidance codes
	TCPStacks     []TCPStackDiagnostic `json:"tcpStacks,omitempty"`
	Report        string            `json:"report"`   // portable plain-text report, without credentials or raw logs
}

 
// TCPStackDiagnostic is a bounded, read-only sample of a running lightweight
// IP stack. It is deliberately omitted when the inbound uses another engine.
type TCPStackDiagnostic struct {
	InboundID string             `json:"inboundId"`
	MTU       int                `json:"mtu"`
	Statistics TCPStackStatistics `json:"statistics"`
	Flows     []TCPFlowDiagnostic `json:"flows"`
}

type TCPStackStatistics struct {
	Connections int64 `json:"connections"`
	MemoryBytes int64 `json:"memoryBytes"`
	PacketsIn uint64 `json:"packetsIn"`
	PacketsOut uint64 `json:"packetsOut"`
	Drops uint64 `json:"drops"`
	Retransmissions uint64 `json:"retransmissions"`
	RSTSent uint64 `json:"rstSent"`
	RSTReceived uint64 `json:"rstReceived"`
	InvalidInputDrops uint64 `json:"invalidInputDrops"`
	RateLimitedDrops uint64 `json:"rateLimitedDrops"`
	OutputAQMDrops uint64 `json:"outputAqmDrops"`
	OutputRejected uint64 `json:"outputRejected"`
	OutputOverloadDrops uint64 `json:"outputOverloadDrops"`
	OutputQueuedPackets int64 `json:"outputQueuedPackets"`
	OutputQueuedBytes int64 `json:"outputQueuedBytes"`
}

type TCPFlowDiagnostic struct {
	State string `json:"state"`
	Local string `json:"local"`
	Remote string `json:"remote"`
	CongestionWindow uint64 `json:"cwndBytes"`
	BytesInFlight uint64 `json:"bytesInFlight"`
	SRTTMilliseconds float64 `json:"srttMs"`
	RTOMilliseconds float64 `json:"rtoMs"`
	PacingRate uint64 `json:"pacingBytesPerSecond"`
	LostBytes uint64 `json:"lostBytes"`
	Retransmissions uint64 `json:"retransmissions"`
	DuplicateACKs int `json:"duplicateAcks"`
	PathMSS int `json:"pathMss"`
	Retries int `json:"retries"`
	Recovering bool `json:"recovering"`
	BBRMode string `json:"bbrMode,omitempty"`
	BBRPhase string `json:"bbrPhase,omitempty"`
}
