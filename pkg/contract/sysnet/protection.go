package sysnet

// Network Protection (kill switch) blocks Internet traffic that does not go
// through Yuhaiin, at the operating system level. The types here are shared
// by every platform: they never name a platform mechanism (PF anchors, pfctl,
// utun). A platform backend translates them.

// Protection states. "protected" is only reported after the backend verified
// that the operating system really enforces the policy; a saved "enabled"
// setting alone is never reported as protected.
const (
	ProtectionUnsupported  = "unsupported"  // no backend on this platform
	ProtectionDisabled     = "disabled"     // not requested
	ProtectionInitializing = "initializing" // requested, not applied or verified yet
	ProtectionProtected    = "protected"    // applied and verified
	ProtectionUpdating     = "updating"     // a policy update is being applied
	ProtectionDegraded     = "degraded"     // blocking, but something is wrong (e.g. Yuhaiin's own traffic is not allowed)
	ProtectionError        = "error"        // requested but not enforced, or the state is unknown
)

// Protection modes. Only the standard kill switch is implemented; the field
// exists so stricter modes can be added without changing the model.
const ProtectionModeStandard = "standard"

// ProtectionSettings are the user's choices. They are stored by the
// privileged protection service, not in Yuhaiin's configuration, so that the
// command line recovery works without the Yuhaiin core and a disabled kill
// switch is never re-enabled by an old configuration.
type ProtectionSettings struct {
	Enabled bool `json:"enabled"`
	// StartAtBoot restores protection when the system starts, before Yuhaiin
	// runs. Without it, protection returns when Yuhaiin starts.
	StartAtBoot bool `json:"startAtBoot"`
}

// ProtectionProblem explains something that is wrong, with a suggested fix.
type ProtectionProblem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitzero"`
}

// Problem codes.
const (
	ProblemPermission       = "permission"        // not running with administrator rights
	ProblemServiceMissing   = "service_missing"   // the protection service is not installed
	ProblemServiceDown      = "service_down"      // the protection service does not answer
	ProblemEnableFailed     = "enable_failed"     // the packet filter could not be enabled
	ProblemRegistration     = "registration"      // the system ruleset does not evaluate Yuhaiin's rules
	ProblemRulesRejected    = "rules_rejected"    // the generated rules were rejected
	ProblemModified         = "modified"          // another program changed or removed Yuhaiin's rules
	ProblemInterfaces       = "interfaces"        // interfaces could not be listed
	ProblemPolicySync       = "policy_sync"       // the policy could not be sent or applied
	ProblemOwnTraffic       = "own_traffic"       // Yuhaiin's own connections cannot be identified
	ProblemState            = "state"             // the saved protection state is damaged
	ProblemTunnelMissing    = "tunnel_missing"    // no Yuhaiin TUN is running, all Internet traffic is blocked
	ProblemBypassIgnored    = "bypass_ignored"    // some bypass networks were not allowed
	ProblemBootstrap        = "bootstrap"         // protection at system startup is not guaranteed
	ProblemPreexistingState = "preexisting_state" // connections opened before protection may continue
)

// ProtectionStatus is the runtime state. Desired and effective state are
// reported separately; values a backend cannot measure are null.
type ProtectionStatus struct {
	State     string `json:"state"`
	Supported bool   `json:"supported"`
	// Backend identifies the mechanism ("pf" on macOS), BackendName is for display.
	Backend     string `json:"backend,omitzero"`
	BackendName string `json:"backendName,omitzero"`
	Mode        string `json:"mode,omitzero"`
	// Desired is the saved request; Effective whether the OS enforces it now.
	Desired   ProtectionSettings `json:"desired"`
	Effective bool               `json:"effective"`
	// Service is the privileged protection service: running, unreachable,
	// not_installed or "" where none is used.
	Service string `json:"service,omitzero"`
	// ServiceVersion is the build of the running protection service. It
	// differs from Yuhaiin's own build until the service is restarted after
	// an update.
	ServiceVersion string `json:"serviceVersion,omitzero"`
	// Filter is the operating system packet filter.
	Filter ProtectionFilter `json:"filter"`
	// CheckedAt is when the OS state was last read, UpdatedAt the last
	// successful policy update (Unix seconds).
	CheckedAt int64               `json:"checkedAt,omitzero"`
	UpdatedAt int64               `json:"updatedAt,omitzero"`
	Error     string              `json:"error,omitzero"`
	Problems  []ProtectionProblem `json:"problems,omitzero"`
	// Traffic policy currently enforced.
	PhysicalInterfaces []string `json:"physicalInterfaces"`
	TunnelInterfaces   []string `json:"tunnelInterfaces"`
	PrivateNetworks    []string `json:"privateNetworks"`
	BypassNetworks     []string `json:"bypassNetworks"`
	// BypassCount is the full count; BypassNetworks may be truncated.
	BypassCount int `json:"bypassCount"`
	// OwnTraffic describes how Yuhaiin's own connections (to proxy servers,
	// tunnel endpoints, DNS servers and direct destinations) are allowed.
	OwnTraffic ProtectionOwnTraffic `json:"ownTraffic"`
	// TunnelIPv4/IPv6 report whether a Yuhaiin tunnel carries the family;
	// without one, public traffic of that family is blocked.
	TunnelIPv4 bool `json:"tunnelIpv4"`
	TunnelIPv6 bool `json:"tunnelIpv6"`
	// Blocked counts packets the protection rule rejected since it was
	// loaded; null when the backend cannot read it.
	Blocked *ProtectionCounters `json:"blocked"`
}

// ProtectionFilter is the platform packet filter state. Pointers are null
// when unknown.
type ProtectionFilter struct {
	// Enabled reports whether the packet filter is on.
	Enabled *bool `json:"enabled"`
	// Registered: the system ruleset evaluates Yuhaiin's rules now.
	Registered *bool `json:"registered"`
	// Persistent: the registration survives a restart (saved system configuration).
	Persistent *bool `json:"persistent"`
	// Loaded: Yuhaiin's protection rules are present.
	Loaded *bool `json:"loaded"`
	// Reference: Yuhaiin holds its own enable reference, so other programs
	// turning the filter off for themselves do not turn it off for Yuhaiin.
	Reference *bool `json:"reference"`
	// Name is the platform's name of Yuhaiin's rule set, for diagnostics.
	Name string `json:"name,omitzero"`
}

// ProtectionOwnTraffic explains how Yuhaiin's own connections pass.
type ProtectionOwnTraffic struct {
	Allowed bool `json:"allowed"`
	// Method is "socket_group" (connections opened by the Yuhaiin process).
	Method string `json:"method,omitzero"`
	Group  string `json:"group,omitzero"`
	// GroupID is the numeric group of Yuhaiin's sockets (0 when none).
	GroupID int `json:"groupId,omitzero"`
	// Connections is the number of connections Yuhaiin itself has open
	// through the protection; null when unknown.
	Connections *int   `json:"connections"`
	Reason      string `json:"reason,omitzero"`
}

type ProtectionCounters struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	// LastAt is when the counter was last seen increasing (Unix seconds);
	// null when no increase was observed.
	LastAt *int64 `json:"lastAt"`
}
