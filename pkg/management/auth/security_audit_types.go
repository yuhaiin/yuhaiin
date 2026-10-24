package auth

import "strconv"

type AuditSettings struct {
	InstanceID         string `json:"instanceId"`
	Revision           uint64 `json:"revision"`
	MaxEvents          int    `json:"maxEvents"`
	MaxAgeDays         int    `json:"maxAgeDays"`
	ForwardEnabled     bool   `json:"forwardEnabled"`
	Transport          string `json:"transport"`
	Endpoint           string `json:"endpoint" secret:"true"`
	EndpointConfigured bool   `json:"endpointConfigured"`
	Destination        string `json:"destination"`
	TokenConfigured    bool   `json:"tokenConfigured"`
	OutboxLimit        int    `json:"outboxLimit"`
}
type AuditSettingsRequest struct {
	AuditSettings
	Token         string `json:"token,omitempty" secret:"true"`
	ClearToken    bool   `json:"clearToken,omitzero"`
	ClearEndpoint bool   `json:"clearEndpoint,omitzero"`
}
type auditConfiguration struct {
	AuditSettings
	token string
}

type AuditRecord struct {
	ID             string `json:"id"`
	OccurredAt     int64  `json:"occurredAt"`
	Event          string `json:"event"`
	ActorID        string `json:"actorId"`
	SubjectID      string `json:"subjectId"`
	Source         string `json:"source"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	CredentialID   string `json:"credentialId"`
	Result         string `json:"result"`
	Changes        string `json:"changes"`
	AuthMethod     string `json:"authMethod"`
	PolicyRevision string `json:"policyRevision"`
	Reason         string `json:"reason"`
}

func auditRecord(event SecurityEvent) AuditRecord {
	return AuditRecord{ID: strconv.FormatInt(event.ID, 10), OccurredAt: event.OccurredAt, Event: event.Event, ActorID: event.ActorID, SubjectID: event.SubjectID, Source: event.Source, Method: event.Method, Path: event.Path, CredentialID: event.CredentialID, Result: event.Result, Changes: event.Changes, AuthMethod: event.AuthMethod, PolicyRevision: event.PolicyRevision, Reason: event.Reason}
}

type AuditQuery struct {
	Cursor                                                        string
	Limit                                                         int
	Event, ActorID, SubjectID, Result, AuthMethod, Reason, Search string
	From, To                                                      int64
}
type AuditPage struct {
	InstanceID string        `json:"instanceId"`
	Items      []AuditRecord `json:"items"`
	NextCursor string        `json:"nextCursor"`
}
type AuditStatus struct {
	Running            bool   `json:"running"`
	Backlog            int    `json:"backlog"`
	OldestQueuedAt     int64  `json:"oldestQueuedAt"`
	Dropped            string `json:"dropped"`
	DeliveryFailures   string `json:"deliveryFailures"`
	Delivered          string `json:"delivered"`
	LastSuccess        int64  `json:"lastSuccess"`
	LastFailure        int64  `json:"lastFailure"`
	LastError          string `json:"lastError"`
	LocalWriteFailures string `json:"localWriteFailures"`
}
