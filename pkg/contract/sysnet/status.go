package sysnet

// Rule and manager states.
const (
	StateActive      = "active"      // applied to the operating system
	StatePending     = "pending"     // saved, not applied yet
	StateDegraded    = "degraded"    // partly applied, or kept from a previous success
	StateConflict    = "conflict"    // some prefixes are owned by other interfaces
	StateUnavailable = "unavailable" // the target interface or TUN does not exist now
	StateUnsupported = "unsupported" // this platform cannot apply the rule
	StateDisabled    = "disabled"
	StateFailed      = "failed"
)

// Interface ownership.
const (
	OwnerYuhaiin  = "yuhaiin"  // a TUN created by a Yuhaiin inbound
	OwnerExternal = "external" // a tunnel created by another program (WireGuard, Tailscale, ...)
	OwnerSystem   = "system"   // physical, loopback and other OS-managed interfaces
)

// Capabilities describes what this platform's adapter can apply. The editor
// only offers supported targets and features.
type Capabilities struct {
	Platform           string `json:"platform"`
	RouteManagement    bool   `json:"routeManagement"`
	MultipleTargets    bool   `json:"multipleTargets"`
	ExternalInterfaces bool   `json:"externalInterfaces"`
	Gateways           bool   `json:"gateways"`
	PolicyRouting      bool   `json:"policyRouting"`
	IPv4Forwarding     bool   `json:"ipv4Forwarding"`
	IPv6Forwarding     bool   `json:"ipv6Forwarding"`
	NAT                bool   `json:"nat"`
	// ForwardSourceFilter reports whether forwarding can be limited to
	// source CIDRs. Without it a rule forwards every device on its ingress.
	ForwardSourceFilter bool     `json:"forwardSourceFilter"`
	TProxy              bool     `json:"tproxy"`
	RouteTargets        []string `json:"routeTargets"`
	ForwardTargets      []string `json:"forwardTargets"`
	Notes               []string `json:"notes,omitzero"`
}

// Status is the runtime state of the System Network Manager.
type Status struct {
	State        string           `json:"state"`
	Error        string           `json:"error,omitzero"`
	Generation   uint64           `json:"generation"`
	AppliedAt    int64            `json:"appliedAt,omitzero"`
	Routes       int              `json:"routes"`
	Rules        []RuleStatus     `json:"rules"`
	Forwarding   ForwardingStatus `json:"forwarding"`
	Required     []RequiredRoutes `json:"required,omitzero"`
	Capabilities Capabilities     `json:"capabilities"`
	Migrations   []Migration      `json:"migrations,omitzero"`
}

// RuleStatus is the runtime state of one route rule.
type RuleStatus struct {
	ID             string `json:"id"`
	State          string `json:"state"`
	Error          string `json:"error,omitzero"`
	Interface      string `json:"interface,omitzero"`
	InterfaceIndex int    `json:"interfaceIndex,omitzero"`
	IPv4Routes     int    `json:"ipv4Routes"`
	IPv6Routes     int    `json:"ipv6Routes"`
	// Conflicts are prefixes left to routes other programs already installed.
	Conflicts []string `json:"conflicts,omitzero"`
	// OverriddenBy lists higher-priority rules that take some of this rule's
	// destinations; Shadowed means they take all of them.
	OverriddenBy []string `json:"overriddenBy,omitzero"`
	Shadowed     bool     `json:"shadowed,omitzero"`
	// Stale is set when routes from the last successful generation are kept
	// because regeneration failed (for example, the GeoIP database is missing).
	Stale bool `json:"stale,omitzero"`
}

// RequiredRoutes are routes a running TUN needs to work (FakeIP pools, its
// subnet on macOS). They are owned by the manager and take precedence over
// route rules.
type RequiredRoutes struct {
	InboundID string   `json:"inboundId"`
	Interface string   `json:"interface"`
	Prefixes  []string `json:"prefixes"`
	Conflicts []string `json:"conflicts,omitzero"`
}

type ForwardingStatus struct {
	State string              `json:"state"`
	Error string              `json:"error,omitzero"`
	IPv4  bool                `json:"ipv4"`
	IPv6  bool                `json:"ipv6"`
	Rules []ForwardRuleStatus `json:"rules"`
}

type ForwardRuleStatus struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Error      string `json:"error,omitzero"`
	Ingress    string `json:"ingress,omitzero"`
	Egress     string `json:"egress,omitzero"`
	Masquerade bool   `json:"masquerade,omitzero"`
}

// Interface is a network interface currently present on the system.
type Interface struct {
	Name         string   `json:"name"`
	Index        int      `json:"index"`
	Type         string   `json:"type"`
	Up           bool     `json:"up"`
	MTU          int      `json:"mtu"`
	HardwareAddr string   `json:"hardwareAddr,omitzero"`
	Addresses    []string `json:"addresses"`
	Gateway      string   `json:"gateway,omitzero"`
	GatewayV6    string   `json:"gatewayV6,omitzero"`
	PointToPoint bool     `json:"pointToPoint,omitzero"`
	Ownership    string   `json:"ownership"`
	InboundID    string   `json:"inboundId,omitzero"`
	InboundName  string   `json:"inboundName,omitzero"`
	// Routable reports whether route rules can target this interface here.
	Routable bool `json:"routable"`
}

// Interfaces lists current interfaces and saved targets that are missing.
type Interfaces struct {
	Items []Interface `json:"items"`
	// TunInbounds are TUN inbounds known to the runtime, running or not.
	TunInbounds []TunInbound `json:"tunInbounds"`
	// TProxyInbounds can receive intercepted forwarded traffic (Linux).
	TProxyInbounds []TProxyInbound `json:"tproxyInbounds,omitzero"`
	// Missing are saved targets whose interface does not exist now.
	Missing []MissingTarget `json:"missing,omitzero"`
}

type TunInbound struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Running   bool   `json:"running"`
	Interface string `json:"interface,omitzero"`
	Platform  bool   `json:"platform,omitzero"`
}

type TProxyInbound struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Listen string `json:"listen"`
}

type MissingTarget struct {
	Target  RouteTarget `json:"target"`
	RuleIDs []string    `json:"ruleIds"`
}

// Preview describes what saving a configuration would install, without
// changing the operating system.
type Preview struct {
	Routes int           `json:"routes"`
	Rules  []RulePreview `json:"rules"`
	Error  string        `json:"error,omitzero"`
}

type RulePreview struct {
	ID           string   `json:"id"`
	IPv4Routes   int      `json:"ipv4Routes"`
	IPv6Routes   int      `json:"ipv6Routes"`
	OverriddenBy []string `json:"overriddenBy,omitzero"`
	Shadowed     bool     `json:"shadowed,omitzero"`
	Error        string   `json:"error,omitzero"`
	// Sample holds the first generated prefixes, for display.
	Sample []string `json:"sample,omitzero"`
}

// SaveResult is returned after saving: the saved configuration and the
// runtime status after applying it. A successful save can still carry an
// apply failure in Status.
type SaveResult struct {
	Config Config `json:"config"`
	Status Status `json:"status"`
}
