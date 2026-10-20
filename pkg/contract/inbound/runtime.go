package inbound

// RuntimeStatus reports listener initialization and cumulative ingress by inbound ID.
// These counters do not imply that forwarding to a destination succeeded.
type RuntimeStatus struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Enabled    bool              `json:"enabled"`
	Status     string            `json:"status"`
	LastError  string            `json:"lastError,omitempty"`
	ChangedAt  int64             `json:"changedAt"` // Unix seconds
	Listeners  []RuntimeListener `json:"listeners"`
	Statistics IngressStatistics `json:"statistics"`
}

type RuntimeListener struct {
	Kind   string `json:"kind"`
	State  string `json:"state"`
	Listen string `json:"listen,omitempty"` // Socket address when available; otherwise the configured address.
}

// IngressTotals is the numeric on-disk representation of the three counters.
// API responses remain decimal strings to preserve precision in JavaScript.
type IngressTotals struct {
	AcceptedStreams uint64
	ReceivedPackets uint64
	ReceivedPings   uint64
}

type IngressStatistics struct {
	AcceptedStreams string `json:"acceptedStreams"`
	ReceivedPackets string `json:"receivedPackets"`
	ReceivedPings   string `json:"receivedPings"`
}

type RuntimeEvent struct {
	ID        uint64 `json:"id"`
	InboundID string `json:"inboundId"`
	Type      string `json:"type"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	CreatedAt int64  `json:"createdAt"` // Unix seconds
}
