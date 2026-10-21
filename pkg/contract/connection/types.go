package connection

import "time"

type Counter struct {
	Download string `json:"download"`
	Upload   string `json:"upload"`
}

type TotalFlow struct {
	Download string             `json:"download"`
	Upload   string             `json:"upload"`
	Counters map[string]Counter `json:"counters,omitzero"`
}

// TrafficPoint is an UTC bucket in a traffic time series. Byte counts are
// strings so clients do not lose precision in JavaScript numbers.
type TrafficPoint struct {
	Start    time.Time `json:"start"`
	Download string    `json:"download"`
	Upload   string    `json:"upload"`
}

type TrafficSeries struct {
	Interval string         `json:"interval"`
	Items    []TrafficPoint `json:"items"`
}

type TelemetryItem struct {
	Value    string `json:"value"`
	Download string `json:"download"`
	Upload   string `json:"upload"`
	Failures string `json:"failures"`
}

type TelemetryGroup struct {
	Dimension string          `json:"dimension"`
	Items     []TelemetryItem `json:"items"`
}

type TelemetrySummary struct {
	Groups []TelemetryGroup `json:"groups"`
}

type Connection struct {
	ID            string              `json:"id"`
	Addr          string              `json:"addr"`
	Network       NetworkType         `json:"network"`
	Source        string              `json:"source"`
	Inbound       string              `json:"inbound"`
	InboundName   string              `json:"inboundName"`
	InboundID     string              `json:"inboundId"`
	Interface     string              `json:"interface"`
	Outbound      string              `json:"outbound"`
	LocalAddr     string              `json:"localAddr"`
	Destination   string              `json:"destination"`
	FakeIP        string              `json:"fakeIp"`
	Hosts         string              `json:"hosts"`
	Domain        string              `json:"domain"`
	IP            string              `json:"ip"`
	SelectorID    string              `json:"selectorId"`
	SelectorName  string              `json:"selectorName"`
	RuleID        string              `json:"ruleId"`
	RuleName      string              `json:"ruleName"`
	NodeID        string              `json:"nodeId"`
	NodeName      string              `json:"nodeName"`
	Protocol      string              `json:"protocol"`
	Process       string              `json:"process"`
	PID           string              `json:"pid"`
	UID           string              `json:"uid"`
	TLSServerName string              `json:"tlsServerName"`
	HTTPHost      string              `json:"httpHost"`
	Component     string              `json:"component"`
	UDPMigrateID  string              `json:"udpMigrateId"`
	Mode          string              `json:"mode"`
	MatchHistory  []MatchHistoryEntry `json:"matchHistory,omitzero"`
	Resolver      string              `json:"resolver"`
	Geo           string              `json:"geo"`
	OutboundGeo   string              `json:"outboundGeo"`
	ListNames     map[string]string   `json:"listNames,omitempty"`
	Lists         []string            `json:"lists,omitzero"`
}

type NetworkType struct {
	ConnType       string `json:"connType"`
	UnderlyingType string `json:"underlyingType"`
}

type MatchHistoryEntry struct {
	RuleID        string              `json:"ruleId,omitempty"`
	RuleName      string              `json:"ruleName"`
	History       []MatchResult       `json:"history"`
	Trace         *MatchTrace         `json:"trace,omitempty"`
	TraceTemplate *MatchTraceTemplate `json:"-"`
}

// MatchTrace preserves the actual boolean evaluation hierarchy and distinguishes
// short-circuited expressions from false and unavailable/unknown results.
type MatchTrace struct {
	Type     string       `json:"type"`
	Label    string       `json:"label,omitempty"`
	State    string       `json:"state"`
	Kind     string       `json:"kind,omitempty"`
	ID       string       `json:"id,omitempty"`
	Children []MatchTrace `json:"children,omitempty"`
}

// MatchTraceRequest selects one active connection for lazy trace expansion.
type MatchTraceRequest struct {
	ID        string `json:"id"`
	RuleIndex int    `json:"ruleIndex"`
}

type MatchTraceResponse struct {
	RuleIndex int               `json:"ruleIndex"`
	Entry     MatchHistoryEntry `json:"entry"`
}

type MatchResult struct {
	Kind     string `json:"kind,omitempty"`
	ID       string `json:"id,omitempty"`
	ListName string `json:"listName"`
	Matched  bool   `json:"matched"`
}

type Connections struct {
	Connections []Connection `json:"connections"`
}

type CloseRequest struct {
	IDs []string `json:"ids"`
}

type FailedHistory struct {
	Protocol    string    `json:"protocol"`
	Host        string    `json:"host"`
	Error       string    `json:"error"`
	Process     string    `json:"process"`
	Time        time.Time `json:"time"`
	FailedCount string    `json:"failedCount"`
}

type FailedHistoryList struct {
	Items              []FailedHistory `json:"items"`
	DumpProcessEnabled bool            `json:"dumpProcessEnabled"`
}

type AllHistory struct {
	Connection Connection `json:"connection"`
	Count      string     `json:"count"`
	Time       time.Time  `json:"time"`
}

type AllHistoryList struct {
	Items              []AllHistory `json:"items"`
	DumpProcessEnabled bool         `json:"dumpProcessEnabled"`
}

type Event struct {
	Type    string `json:"type"`
	Payload any    `json:"payload,omitzero"`
}

// SessionSummary contains runtime-only session counts and bytes. Lifetime totals
// remain persisted by TotalCache. Decimal strings preserve full counter precision.
type SessionSummary struct {
	Download      string `json:"download"`
	Upload        string `json:"upload"`
	TotalDownload string `json:"totalDownload"`
	TotalUpload   string `json:"totalUpload"`
	Active        int    `json:"active"`
	Opened        string `json:"opened"`
	Failed        string `json:"failed"`
}
