package node

// ProbeStatus records the result of an explicit connectivity test. Test results
// are observations, not a guarantee that a future connection will succeed.
type ProbeStatus struct {
	CheckedAt int64           `json:"checkedAt"`
	Result    LatencyResponse `json:"result"`
}

// RuntimeStatus has stable node identity even when its Proxy instance is
// evicted or reconfigured. Byte/packet totals are decimal strings so browsers
// do not lose precision beyond JavaScript's 53-bit integer limit.
type RuntimeStatus struct {
	ID                string                  `json:"id"`
	State             string                  `json:"state"`
	UploadBytes       string                  `json:"uploadBytes"`
	DownloadBytes     string                  `json:"downloadBytes"`
	UploadBps         string                  `json:"uploadBps"`
	DownloadBps       string                  `json:"downloadBps"`
	UDPSentPackets    string                  `json:"udpSentPackets"`
	UDPRecvPackets    string                  `json:"udpRecvPackets"`
	TCPAttempts       string                  `json:"tcpAttempts"`
	TCPConnections    string                  `json:"tcpConnections"`
	UDPAttempts       string                  `json:"udpAttempts"`
	UDPSessions       string                  `json:"udpSessions"`
	PingAttempts      string                  `json:"pingAttempts"`
	Failures          string                  `json:"failures"`
	ActiveTCP         int64                   `json:"activeTCP"`
	ActiveUDP         int64                   `json:"activeUDP"`
	LastSuccessAt     int64                   `json:"lastSuccessAt"`
	LastFailureAt     int64                   `json:"lastFailureAt"`
	LastUsedAt        int64                   `json:"lastUsedAt"`
	LastError         string                  `json:"lastError,omitempty"`
	Probes            map[string]ProbeStatus  `json:"probes,omitempty"`
	Protocol          *ProtocolRuntimeStatus  `json:"protocol,omitempty"`
	TCPHealth         ChannelHealth           `json:"tcpHealth"`
	UDPHealth         ChannelHealth           `json:"udpHealth"`
	ThroughputHistory []ThroughputMeasurement `json:"throughputHistory,omitempty"`
	Throughput        ThroughputMeasurement   `json:"throughput"`
}

// ChannelHealth separates real remote evidence from constructing a proxy or
// opening a lazy UDP session. Samples are bounded and shared by selectors.
type ChannelHealth struct {
	State                string         `json:"state"`
	ConsecutiveFailures  int            `json:"consecutiveFailures"`
	ConsecutiveSuccesses int            `json:"consecutiveSuccesses"`
	Samples              []HealthSample `json:"samples,omitempty"`
	LatencySamples       []HealthSample `json:"latencySamples,omitempty"`
}

type HealthSample struct {
	At      int64   `json:"at"`
	OK      bool    `json:"ok"`
	Timeout bool    `json:"timeout,omitzero"`
	RTTMS   float64 `json:"rttMs,omitzero"`
	Kind    string  `json:"kind"`
	Target  string  `json:"target,omitempty"`
}

// ThroughputMeasurement is an active, target-specific approximate measurement,
// independent of current business traffic in UploadBps/DownloadBps.
type ThroughputMeasurement struct {
	At           int64   `json:"at"`
	OK           bool    `json:"ok"`
	Target       string  `json:"target"`
	DownloadMbps float64 `json:"downloadMbps"`
	UploadMbps   float64 `json:"uploadMbps,omitzero"`
	Bytes        int64   `json:"bytes"`
	DurationMS   int64   `json:"durationMs"`
	Samples      int     `json:"samples"`
	Error        string  `json:"error,omitempty"`
}

type SelectorCandidateStatus struct {
	NodeID            string                   `json:"nodeId"`
	Eligible          bool                     `json:"eligible"`
	Reason            string                   `json:"reason"`
	State             string                   `json:"state"`
	RTTMS             float64                  `json:"rttMs"`
	JitterMS          float64                  `json:"jitterMs"`
	FailureRate       float64                  `json:"failureRate"`
	Samples           int                      `json:"samples"`
	DownloadMbps      float64                  `json:"downloadMbps"`
	UploadMbps        float64                  `json:"uploadMbps"`
	ActiveConnections int64                    `json:"activeConnections"`
	Score             float64                  `json:"score"`
	Components        *SelectorScoreComponents `json:"components,omitzero"`
}

type SelectorDecision struct {
	NodeID     string                    `json:"nodeId"`
	Reason     string                    `json:"reason"`
	Since      int64                     `json:"since"`
	Candidates []SelectorCandidateStatus `json:"candidates"`
}

type SelectorEvent struct {
	At      int64  `json:"at"`
	Network string `json:"network"`
	From    string `json:"from"`
	To      string `json:"to"`
	Reason  string `json:"reason"`
}

type SelectorRuntimeStatus struct {
	ID         string           `json:"id"`
	Revision   uint64           `json:"revision"`
	TCP        SelectorDecision `json:"tcp"`
	UDP        SelectorDecision `json:"udp"`
	Events     []SelectorEvent  `json:"events"`
	Switches   uint64           `json:"switches"`
	Suppressed uint64           `json:"suppressed"`
}

// NodeRuntimeStatusProvider is an optional extension for protocol implementations
// that can report a genuine native tunnel session state, e.g. WireGuard or
// OpenVPN. The generic observer never infers VPN handshake state from a dial.
type NodeRuntimeStatusProvider interface {
	NodeRuntimeStatus() ProtocolRuntimeStatus
}

type ProtocolRuntimeStatus struct {
	State     string `json:"state"`
	LastError string `json:"lastError,omitempty"`
	UpdatedAt int64  `json:"updatedAt"`
}

// SelectorScoreComponents exposes normalized inputs separately from weights.
type SelectorScoreComponents struct {
	RTT       float64 `json:"rtt"`
	Download  float64 `json:"download"`
	Upload    float64 `json:"upload"`
	Stability float64 `json:"stability"`
	Jitter    float64 `json:"jitter"`
	Load      float64 `json:"load"`
}
