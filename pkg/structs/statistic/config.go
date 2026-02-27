package statistic

import (
	"github.com/Asutorufa/yuhaiin/pkg/structs/config"
)

type Type int32

const (
	TypeUnknown    Type = 0
	TypeTcp        Type = 1
	TypeTcp4       Type = 2
	TypeTcp6       Type = 3
	TypeUdp        Type = 4
	TypeUdp4       Type = 5
	TypeUdp6       Type = 6
	TypeIp         Type = 7
	TypeIp4        Type = 8
	TypeIp6        Type = 9
	TypeUnix       Type = 10
	TypeUnixgram   Type = 11
	TypeUnixpacket Type = 12
)

type NetType struct {
	ConnType       Type `json:"conn_type"`
	UnderlyingType Type `json:"underlying_type"`
}

type Connection struct {
	Addr          string               `json:"addr"`
	Id            uint64               `json:"id"`
	Type          NetType              `json:"type"`
	Source        string               `json:"source"`
	Inbound       string               `json:"inbound"`
	InboundName   string               `json:"inbound_name"`
	Interface     string               `json:"interface"`
	Outbound      string               `json:"outbound"`
	LocalAddr     string               `json:"LocalAddr"`
	Destionation  string               `json:"destionation"`
	FakeIp        string               `json:"fake_ip"`
	Hosts         string               `json:"hosts"`
	Domain        string               `json:"domain"`
	Ip            string               `json:"ip"`
	Tag           string               `json:"tag"`
	Hash          string               `json:"hash"`
	NodeName      string               `json:"node_name"`
	Protocol      string               `json:"protocol"`
	Process       string               `json:"process"`
	Pid           uint64               `json:"pid"`
	Uid           uint64               `json:"uid"`
	TlsServerName string               `json:"tls_server_name"`
	HttpHost      string               `json:"http_host"`
	Component     string               `json:"component"`
	UdpMigrateId  uint64               `json:"udp_migrate_id"`
	Mode          config.Mode          `json:"mode"`
	MatchHistory  []MatchHistoryEntry `json:"match_history"`
	Resolver      string               `json:"resolver"`
	Geo           string               `json:"geo"`
	OutboundGeo   string               `json:"outbound_geo"`
	Lists         []string             `json:"lists"`
}

type MatchResult struct {
	ListName string `json:"list_name"`
	Matched  bool   `json:"matched"`
}

type MatchHistoryEntry struct {
	RuleName string        `json:"rule_name"`
	History  []MatchResult `json:"history"`
}
