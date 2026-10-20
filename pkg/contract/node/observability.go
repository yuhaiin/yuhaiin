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
	ID             string                 `json:"id"`
	State          string                 `json:"state"`
	UploadBytes    string                 `json:"uploadBytes"`
	DownloadBytes  string                 `json:"downloadBytes"`
	UploadBps      string                 `json:"uploadBps"`
	DownloadBps    string                 `json:"downloadBps"`
	UDPSentPackets string                 `json:"udpSentPackets"`
	UDPRecvPackets string                 `json:"udpRecvPackets"`
	TCPAttempts    string                 `json:"tcpAttempts"`
	TCPConnections string                 `json:"tcpConnections"`
	UDPAttempts    string                 `json:"udpAttempts"`
	UDPSessions    string                 `json:"udpSessions"`
	PingAttempts   string                 `json:"pingAttempts"`
	Failures       string                 `json:"failures"`
	ActiveTCP      int64                  `json:"activeTCP"`
	ActiveUDP      int64                  `json:"activeUDP"`
	LastSuccessAt  int64                  `json:"lastSuccessAt"`
	LastFailureAt  int64                  `json:"lastFailureAt"`
	LastUsedAt     int64                  `json:"lastUsedAt"`
	LastError      string                 `json:"lastError,omitempty"`
	Probes         map[string]ProbeStatus `json:"probes,omitempty"`
	Protocol       *ProtocolRuntimeStatus `json:"protocol,omitempty"`
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
