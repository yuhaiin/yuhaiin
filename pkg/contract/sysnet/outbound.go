package sysnet

// Egress modes of Yuhaiin's own outbound sockets.
const (
	// EgressKernel: protected sockets are not bound; the kernel routes each
	// packet by destination (Linux with SO_MARK).
	EgressKernel = "kernel"
	// EgressBound: each socket is bound to the interface the OS would use
	// for its destination with Yuhaiin's TUN excluded (macOS, Windows,
	// Linux without SO_MARK).
	EgressBound = "bound"
	// EgressExplicit: a configured interface pins every outbound socket.
	EgressExplicit = "explicit"
	// EgressSystem: no TUN of Yuhaiin's is up; sockets follow the OS.
	EgressSystem = "system"
)

// OutboundRouting is the runtime state of Socket Protection (keeping sockets
// Yuhaiin opens for itself out of its own TUN) and Egress Selection (which
// interface they leave through). It is read-only and independent of the
// route rules, which apply to other applications' traffic.
type OutboundRouting struct {
	Platform string `json:"platform"`
	State    string `json:"state"`
	// Method is the protection mechanism: SO_MARK, IP_BOUND_IF,
	// IP_UNICAST_IF or VpnService.protect.
	Method            string   `json:"method"`
	Mark              uint32   `json:"mark,omitzero"`
	ProtectionActive  bool     `json:"protectionActive"`
	EgressMode        string   `json:"egressMode"`
	ExplicitInterface string   `json:"explicitInterface,omitzero"`
	OwnTuns           []string `json:"ownTuns"`
	// Successes and Failures count protected sockets since start.
	Successes uint64 `json:"successes"`
	Failures  uint64 `json:"failures"`
	LastError string `json:"lastError,omitzero"`
	// Problems explain a degraded or failed state, with what to do.
	Problems []string `json:"problems,omitzero"`
	// Rules are the Linux policy rules that exclude the mark from the TUN.
	Rules []OutboundPolicyRule `json:"rules,omitzero"`
	// Egress is the interface chosen now for Internet destinations.
	Egress     []OutboundEgress    `json:"egress"`
	Interfaces []OutboundInterface `json:"interfaces"`
}

type OutboundPolicyRule struct {
	IPv6     bool   `json:"ipv6"`
	Priority int    `json:"priority"`
	Selector string `json:"selector"`
	Table    int    `json:"table"`
	State    string `json:"state"`
	Error    string `json:"error,omitzero"`
}

// OutboundEgress is the selection for one family's Internet destinations.
type OutboundEgress struct {
	IPv6      bool   `json:"ipv6"`
	Interface string `json:"interface,omitzero"`
	Gateway   string `json:"gateway,omitzero"`
	Prefix    string `json:"prefix,omitzero"`
	Metric    uint32 `json:"metric,omitzero"`
	Error     string `json:"error,omitzero"`
}

// OutboundInterface is one interface as Egress Selection sees it.
type OutboundInterface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	Type      string   `json:"type"`
	Up        bool     `json:"up"`
	Ownership string   `json:"ownership"`
	Addresses []string `json:"addresses"`
	Gateway   string   `json:"gateway,omitzero"`
	GatewayV6 string   `json:"gatewayV6,omitzero"`
	// Excluded is set for Yuhaiin's TUNs: never an egress.
	Excluded bool `json:"excluded,omitzero"`
	// DefaultMetric/DefaultMetricV6 are the default routes' metrics
	// (Windows: route plus interface metric).
	DefaultMetric   uint32 `json:"defaultMetric,omitzero"`
	DefaultMetricV6 uint32 `json:"defaultMetricV6,omitzero"`
	// Scoped/ScopedV6 are the macOS interface-scoped default routes.
	Scoped   OutboundScopedRoute `json:"scoped,omitzero"`
	ScopedV6 OutboundScopedRoute `json:"scopedV6,omitzero"`
}

// OutboundScopedRoute is a macOS interface-scoped default route.
type OutboundScopedRoute struct {
	// State: primary (the global default is here), borrowed (installed by
	// the system or another program), owned (installed by Yuhaiin),
	// unavailable (no router known) or failed.
	State   string `json:"state"`
	Gateway string `json:"gateway,omitzero"`
	Link    bool   `json:"link,omitzero"`
	Reason  string `json:"reason,omitzero"`
}
