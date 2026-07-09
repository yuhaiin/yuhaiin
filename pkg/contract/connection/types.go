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

type Connection struct {
	ID            string              `json:"id"`
	Addr          string              `json:"addr"`
	Network       NetworkType         `json:"network"`
	Source        string              `json:"source"`
	Inbound       string              `json:"inbound"`
	InboundName   string              `json:"inboundName"`
	Interface     string              `json:"interface"`
	Outbound      string              `json:"outbound"`
	LocalAddr     string              `json:"localAddr"`
	Destination   string              `json:"destination"`
	FakeIP        string              `json:"fakeIp"`
	Hosts         string              `json:"hosts"`
	Domain        string              `json:"domain"`
	IP            string              `json:"ip"`
	Tag           string              `json:"tag"`
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
	Lists         []string            `json:"lists,omitzero"`
}

type NetworkType struct {
	ConnType       string `json:"connType"`
	UnderlyingType string `json:"underlyingType"`
}

type MatchHistoryEntry struct {
	RuleName string        `json:"ruleName"`
	History  []MatchResult `json:"history"`
}

type MatchResult struct {
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
