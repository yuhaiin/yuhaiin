package api

import (
	"github.com/Asutorufa/yuhaiin/pkg/config"
	"github.com/Asutorufa/yuhaiin/pkg/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
)

// --- config.proto ---

type RuleIndex struct {
	Index uint32 `json:"index,omitempty"`
	Name  string `json:"name,omitempty"`
}

type RuleSaveRequest struct {
	Index *RuleIndex       `json:"index,omitempty"`
	Rule  *config.RuleV2   `json:"rule,omitempty"`
}

type ChangePriorityOperate int32

const (
	Exchange     ChangePriorityOperate = 0
	InsertBefore ChangePriorityOperate = 1
	InsertAfter  ChangePriorityOperate = 2
)

type ChangePriorityRequest struct {
	Source  *RuleIndex            `json:"source,omitempty"`
	Target  *RuleIndex            `json:"target,omitempty"`
	Operate ChangePriorityOperate `json:"operate,omitempty"`
}

type InboundsResponse struct {
	Names           []string      `json:"names,omitempty"`
	HijackDns       bool          `json:"hijack_dns,omitempty"`
	HijackDnsFakeip bool          `json:"hijack_dns_fakeip,omitempty"`
	Sniff           *config.Sniff `json:"sniff,omitempty"`
}

type PlatformInfoResponse struct {
	Darwin *PlatformDarwin `json:"darwin,omitempty"`
}

type PlatformDarwin struct {
	NetworkServices []string `json:"network_services,omitempty"`
}

type ResolveList struct {
	Names []string `json:"names,omitempty"`
}

type SaveResolver struct {
	Name     string      `json:"name,omitempty"`
	Resolver *config.Dns `json:"resolver,omitempty"`
}

type Hosts struct {
	Hosts map[string]string `json:"hosts,omitempty"`
}

// --- node.proto ---

type NowResp struct {
	Tcp *protocol.Point `json:"tcp,omitempty"`
	Udp *protocol.Point `json:"udp,omitempty"`
}

type UseReq struct {
	Hash string `json:"hash,omitempty"`
}

type NodesResponse struct {
	Groups []*NodesResponseGroup `json:"groups,omitempty"`
}

type NodesResponseGroup struct {
	Name  string               `json:"name,omitempty"`
	Nodes []*NodesResponseNode `json:"nodes,omitempty"`
}

type NodesResponseNode struct {
	Hash string `json:"hash,omitempty"`
	Name string `json:"name,omitempty"`
}

type ActivatesResponse struct {
	Nodes []*protocol.Point `json:"nodes,omitempty"`
}

type SavePublishRequest struct {
	Name    string            `json:"name,omitempty"`
	Publish *protocol.Publish `json:"publish,omitempty"`
}

type ListPublishResponse struct {
	Publishes map[string]*protocol.Publish `json:"publishes,omitempty"`
}

type PublishRequest struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Path     string `json:"path,omitempty"`
}

type PublishResponse struct {
	Points []*protocol.Point `json:"points,omitempty"`
}

type SaveLinkReq struct {
	Links []*protocol.Link `json:"links,omitempty"`
}

type LinkReq struct {
	Names []string `json:"names,omitempty"`
}

type GetLinksResp struct {
	Links map[string]*protocol.Link `json:"links,omitempty"`
}

type SaveTagReq struct {
	Tag  string           `json:"tag,omitempty"`
	Type protocol.TagType `json:"type,omitempty"`
	Hash string           `json:"hash,omitempty"`
}

type TagsResponse struct {
	Tags map[string]*protocol.Tags `json:"tags,omitempty"`
}

// --- statistic.proto ---

type Counter struct {
	Download uint64 `json:"download,omitempty"`
	Upload   uint64 `json:"upload,omitempty"`
}

type TotalFlow struct {
	Download uint64              `json:"download,omitempty"`
	Upload   uint64              `json:"upload,omitempty"`
	Counters map[uint64]*Counter `json:"counters,omitempty"`
}

type NotifyData struct {
	TotalFlow              *TotalFlow               `json:"total_flow,omitempty"`
	NotifyNewConnections   *NotifyNewConnections    `json:"notify_new_connections,omitempty"`
	NotifyRemoveConnections *NotifyRemoveConnections `json:"notify_remove_connections,omitempty"`
}

type NotifyNewConnections struct {
	Connections []*statistics.Connection `json:"connections,omitempty"`
}

type NotifyRemoveConnections struct {
	Ids []uint64 `json:"ids,omitempty"`
}

type FailedHistory struct {
	Protocol    statistics.Type `json:"protocol,omitempty"`
	Host        string          `json:"host,omitempty"`
	Error       string          `json:"error,omitempty"`
	Process     string          `json:"process,omitempty"`
	Time        string          `json:"time,omitempty"` // timestamp string
	FailedCount uint64          `json:"failed_count,omitempty"`
}

type FailedHistoryList struct {
	Objects            []*FailedHistory `json:"objects,omitempty"`
	DumpProcessEnabled bool             `json:"dump_process_enabled,omitempty"`
}

type AllHistory struct {
	Connection *statistics.Connection `json:"connection,omitempty"`
	Count      uint64                 `json:"count,omitempty"`
	Time       string                 `json:"time,omitempty"` // timestamp string
}

type AllHistoryList struct {
	Objects            []*AllHistory `json:"objects,omitempty"`
	DumpProcessEnabled bool          `json:"dump_process_enabled,omitempty"`
}
