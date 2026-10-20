package trafficcontrol

// Status contains only bounded aggregate counters; never publish dynamic
// source IPs, users, destinations or per-flow IDs as metric labels.
type Status struct {
	Global        Counters      `json:"global"`
	NAT           Counters      `json:"nat"`
	Shaping       Usage          `json:"shaping"`
	InboundScopes []ScopeStatus `json:"inboundScopes"`
	Truncated     bool          `json:"truncated"`
}

type ScopeStatus struct {
	ID       string   `json:"id"`
	Counters Counters `json:"counters"`
}
