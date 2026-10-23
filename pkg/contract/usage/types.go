// Package usage defines user traffic observations, independent of identity storage.
package usage

import "errors"

var ErrQuery = errors.New("invalid user usage query")

type Options struct {
	AuditDays    int `json:"auditDays"`
	MaxAuditRows int `json:"maxAuditRows"`
	HourlyDays   int `json:"hourlyDays"`
	DailyDays    int `json:"dailyDays"`
}

// Counters are decimal strings to preserve integer precision in JavaScript.
type Counters struct {
	Upload        string `json:"upload"`
	Download      string `json:"download"`
	Opened        string `json:"opened"`
	Failed        string `json:"failed"`
	SessionMillis string `json:"sessionMillis"`
	FirstSeen     int64  `json:"firstSeen"`
	LastSeen      int64  `json:"lastSeen"`
}

type Summary struct {
	UserID              string   `json:"userId"`
	Lifetime            Counters `json:"lifetime"`
	Period              Counters `json:"period"`
	ActiveTCP           int      `json:"activeTcp"`
	ActiveUDP           int      `json:"activeUdp"`
	PeakTCP             int      `json:"peakTcp"`
	PeakUDP             int      `json:"peakUdp"`
	ActiveMinutes       string   `json:"activeMinutes"`
	PeriodActiveMinutes string   `json:"periodActiveMinutes"`
	UploadRate          string   `json:"uploadRate"`
	DownloadRate        string   `json:"downloadRate"`
}

type Point struct {
	Start int64 `json:"start"`
	Counters
}

type Breakdown struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Counters
}

type Report struct {
	Summary     Summary     `json:"summary"`
	Series      []Point     `json:"series"`
	Nodes       []Breakdown `json:"nodes"`
	Inbounds    []Breakdown `json:"inbounds"`
	Credentials []Breakdown `json:"credentials"`
	Protocols   []Breakdown `json:"protocols"`
	Interval    string      `json:"interval"`
	From        int64       `json:"from"`
	To          int64       `json:"to"`
	UpdatedAt   int64       `json:"updatedAt"`
	Health      Health      `json:"health"`
}

type Health struct {
	PendingAudit     int    `json:"pendingAudit"`
	DroppedAudit     string `json:"droppedAudit"`
	LastFlush        int64  `json:"lastFlush"`
	PersistenceError bool   `json:"persistenceError"`
}

// Query uses half-open UTC intervals. Empty UserID means unattributed traffic;
// authorization and selection of an owner belong to the management module.
type Query struct {
	UserID                                    string
	From, To                                  int64
	Interval                                  string
	CredentialID, InboundID, NodeID, Protocol string
	Result, Source, Target                    string
	Before                                    string
	Limit                                     int
}

// Audit stores connection metadata only. It never contains secrets, URLs,
// headers, request bodies or full rule evaluation traces.
type Audit struct {
	ID             string `json:"id"`
	UserID         string `json:"userId"`
	CredentialID   string `json:"credentialId"`
	InboundID      string `json:"inboundId"`
	InboundName    string `json:"inboundName"`
	NodeID         string `json:"nodeId"`
	NodeName       string `json:"nodeName"`
	SelectorID     string `json:"selectorId"`
	SelectorName   string `json:"selectorName"`
	RuleID         string `json:"ruleId"`
	RuleName       string `json:"ruleName"`
	Protocol       string `json:"protocol"`
	Mode           string `json:"mode"`
	Source         string `json:"source"`
	Target         string `json:"target"`
	IP             string `json:"ip"`
	StartedAt      int64  `json:"startedAt"`
	EndedAt        int64  `json:"endedAt"`
	LastSeen       int64  `json:"lastSeen"`
	DurationMillis string `json:"durationMillis"`
	Upload         string `json:"upload"`
	Download       string `json:"download"`
	Result         string `json:"result"`
	Reason         string `json:"reason"`
}

type AuditPage struct {
	Items  []Audit `json:"items"`
	Next   string  `json:"next"`
	Health Health  `json:"health"`
}
