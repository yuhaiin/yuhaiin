package statistics

import "github.com/Asutorufa/yuhaiin/pkg/config"

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
	ConnType       Type `json:"conn_type,omitempty"`
	UnderlyingType Type `json:"underlying_type,omitempty"`
}

type Connection struct {
	Addr        string      `json:"addr,omitempty"`
	Id          uint64      `json:"id,omitempty"`
	Type        *NetType    `json:"type,omitempty"`
	Source      string      `json:"source,omitempty"`
	Inbound     string      `json:"inbound,omitempty"`
	InboundName string      `json:"inbound_name,omitempty"`
	Interface   string      `json:"interface,omitempty"`
	Outbound    string      `json:"outbound,omitempty"`
	LocalAddr   string      `json:"LocalAddr,omitempty"`
	Destionation string     `json:"destionation,omitempty"`
	FakeIp      string      `json:"fake_ip,omitempty"`
	Hosts       string      `json:"hosts,omitempty"`
	Domain      string      `json:"domain,omitempty"`
	Ip          string      `json:"ip,omitempty"`
	Tag         string      `json:"tag,omitempty"`
	Hash        string      `json:"hash,omitempty"`
	NodeName    string      `json:"node_name,omitempty"`
	Protocol    string      `json:"protocol,omitempty"`
	Process     string      `json:"process,omitempty"`
	Pid         uint64      `json:"pid,omitempty"`
	Uid         uint64      `json:"uid,omitempty"`
	TlsServerName string    `json:"tls_server_name,omitempty"`
	HttpHost    string      `json:"http_host,omitempty"`
	Component   string      `json:"component,omitempty"`
	UdpMigrateId uint64     `json:"udp_migrate_id,omitempty"`
	Mode        config.Mode `json:"mode,omitempty"`
	MatchHistory []*MatchHistoryEntry `json:"match_history,omitempty"`
	Resolver    string      `json:"resolver,omitempty"`
	Geo         string      `json:"geo,omitempty"`
	OutboundGeo string      `json:"outbound_geo,omitempty"`
	Lists       []string    `json:"lists,omitempty"`
}

type MatchResult struct {
	ListName string `json:"list_name,omitempty"`
	Matched  bool   `json:"matched,omitempty"`
}

type MatchHistoryEntry struct {
	RuleName string         `json:"rule_name,omitempty"`
	History  []*MatchResult `json:"history,omitempty"`
}
