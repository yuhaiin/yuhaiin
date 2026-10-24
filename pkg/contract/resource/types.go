// Package resource describes identity-scoped resource policies and live reports.
// It contains no identity database or forwarding implementation.
package resource

type Rate struct {
	BytesPerSecond int64 `json:"bytesPerSecond"`
	BurstBytes     int64 `json:"burstBytes"`
}

type Profile struct {
	Upload   Rate `json:"upload"`
	Download Rate `json:"download"`
}

type Limits struct {
	MaxTCPSessions       int64   `json:"maxTcpSessions"`
	MaxUDPSessions       int64   `json:"maxUdpSessions"`
	MaxSessions          int64   `json:"maxSessions"`
	ConnectionsPerSecond float64 `json:"connectionsPerSecond"`
	ConnectionBurst      float64 `json:"connectionBurst"`
	PacketsPerSecond     float64 `json:"packetsPerSecond"`
	PacketBurst          float64 `json:"packetBurst"`
}

// Decimal strings keep quota sizes exact in JavaScript and SQLite's int64 range.
// Zero is unlimited for that dimension. Period is daily, monthly or lifetime.
type Quota struct {
	ID           string  `json:"id"`
	Period       string  `json:"period"`
	Upload       string  `json:"upload"`
	Download     string  `json:"download"`
	Combined     string  `json:"combined"`
	Action       string  `json:"action"`
	ReducedSpeed Profile `json:"reducedSpeed"`
	Thresholds   []int   `json:"thresholds"`
}

type Policy struct {
	Profile Profile `json:"profile"`
	Limits  Limits  `json:"limits"`
	Quotas  []Quota `json:"quotas"`
}

// SharedProfile and Quotas cover the whole group. IndividualProfile and
// UserLimits apply independently to each member, across that member's devices.
type GroupPolicy struct {
	GroupID           string  `json:"groupId"`
	SharedProfile     Profile `json:"sharedProfile"`
	IndividualProfile Profile `json:"individualProfile"`
	UserLimits        Limits  `json:"userLimits"`
	Quotas            []Quota `json:"quotas"`
}

type UserPolicy struct {
	UserID string `json:"userId"`
	Policy Policy `json:"policy"`
}

type CredentialPolicy struct {
	CredentialID string `json:"credentialId"`
	Policy       Policy `json:"policy"`
}

// Explicit users replace DefaultUser. Group and credential constraints still
// compose with the resulting user policy; they cannot be lifted by an override.
type Config struct {
	Revision    uint64             `json:"revision"`
	Enabled     bool               `json:"enabled"`
	DefaultUser Policy             `json:"defaultUser"`
	Groups      []GroupPolicy      `json:"groups"`
	Users       []UserPolicy       `json:"users"`
	Credentials []CredentialPolicy `json:"credentials"`
}

type Bytes struct {
	Upload   string `json:"upload"`
	Download string `json:"download"`
	Combined string `json:"combined"`
}

// Measured counts accepted edge bytes. Used also includes a conservative
// recovery charge for durable grants whose exact usage was not checkpointed.
type QuotaUsage struct {
	QuotaID        string `json:"quotaId"`
	Scope          string `json:"scope"`
	ScopeID        string `json:"scopeId"`
	Period         string `json:"period"`
	StartsAt       int64  `json:"startsAt"`
	ResetsAt       int64  `json:"resetsAt"`
	Measured       Bytes  `json:"measured"`
	RecoveryCharge Bytes  `json:"recoveryCharge"`
	Used           Bytes  `json:"used"`
	Remaining      Bytes  `json:"remaining"`
	Limit          Bytes  `json:"limit"`
	Action         string `json:"action"`
	Exceeded       bool   `json:"exceeded"`
	Thresholds     []int  `json:"thresholds"`
	Violations     string `json:"violations"`
}

type Sessions struct {
	TCP   int64 `json:"tcp"`
	UDP   int64 `json:"udp"`
	Total int64 `json:"total"`
}

type ScopeUsage struct {
	LastRejection     string   `json:"lastRejection"`
	LastRejectedAt    int64    `json:"lastRejectedAt"`
	Scope             string   `json:"scope"`
	ScopeID           string   `json:"scopeId"`
	Name              string   `json:"name"`
	ConfiguredProfile Profile  `json:"configuredProfile"`
	EnforcedProfile   Profile  `json:"enforcedProfile"`
	ConfiguredLimits  Limits   `json:"configuredLimits"`
	EnforcedLimits    Limits   `json:"enforcedLimits"`
	Sessions          Sessions `json:"sessions"`
	RejectedSessions  string   `json:"rejectedSessions"`
	RejectedPackets   string   `json:"rejectedPackets"`
}

type Report struct {
	Revision            uint64       `json:"revision"`
	Enabled             bool         `json:"enabled"`
	UserID              string       `json:"userId"`
	Scopes              []ScopeUsage `json:"scopes"`
	Quotas              []QuotaUsage `json:"quotas"`
	PersistenceDegraded bool         `json:"persistenceDegraded"`
}

type Alert struct {
	ID         string `json:"id"`
	OccurredAt int64  `json:"occurredAt"`
	Scope      string `json:"scope"`
	ScopeID    string `json:"scopeId"`
	QuotaID    string `json:"quotaId"`
	Period     string `json:"period"`
	StartsAt   int64  `json:"startsAt"`
	Threshold  int    `json:"threshold"`
}

type AlertPage struct {
	Items         []Alert `json:"items"`
	Next          string  `json:"next"`
	RetentionRows int     `json:"retentionRows"`
}

type Status struct {
	Revision                 uint64 `json:"revision"`
	Windows                  int    `json:"windows"`
	PendingWrites            int    `json:"pendingWrites"`
	Denied                   string `json:"denied"`
	PersistenceFailures      string `json:"persistenceFailures"`
	RefreshFailures          string `json:"refreshFailures"`
	DroppedAlerts            string `json:"droppedAlerts"`
	PendingAlerts            int    `json:"pendingAlerts"`
	AlertPersistenceFailures string `json:"alertPersistenceFailures"`
}
