package trafficcontrol

// Status contains only bounded aggregate counters; never publish dynamic
// source IPs, users, destinations or per-flow IDs as metric labels.
type Status struct {
	Queues        []QueueStatus `json:"queues,omitempty"`
	Global        Counters      `json:"global"`
	NAT           Counters      `json:"nat"`
	Shaping       Usage         `json:"shaping"`
	InboundScopes []ScopeStatus `json:"inboundScopes"`
	Truncated     bool          `json:"truncated"`
}

type ScopeStatus struct {
	ID       string   `json:"id"`
	Counters Counters `json:"counters"`
}

// QueueReporter is an optional capability of packet-output adapters. Wrappers
// forward it; unsupported stacks return false rather than reporting fake zeros.
type QueueReporter interface{ TrafficControlQueue() (FairStats, bool) }
type QueueStatus struct {
	ID       string    `json:"id"`
	Counters FairStats `json:"counters"`
}

func (s *Status) AddQueue(id string, counters FairStats) bool {
	if len(s.Queues) >= 64 {
		s.Truncated = true
		return false
	}
	s.Queues = append(s.Queues, QueueStatus{ID: id, Counters: counters})
	return true
}
