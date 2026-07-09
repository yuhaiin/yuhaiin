package api

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"strconv"
	"time"

	schemaconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	schemanode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	schemastatistic "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/statistic"
)

type PageRequest struct {
	Page     uint32 `json:"page"`
	PageSize uint32 `json:"page_size"`
	Query    string `json:"query"`
}

func (x *PageRequest) GetPage() uint32 {
	if x == nil {
		return 0
	}
	return x.Page
}

func (x *PageRequest) SetPage(v uint32) { x.Page = v }

func (x *PageRequest) GetPageSize() uint32 {
	if x == nil {
		return 0
	}
	return x.PageSize
}

func (x *PageRequest) SetPageSize(v uint32) { x.PageSize = v }

func (x *PageRequest) GetQuery() string {
	if x == nil {
		return ""
	}
	return x.Query
}

func (x *PageRequest) SetQuery(v string) { x.Query = v }

type PageResponse struct {
	Page     uint32 `json:"page"`
	PageSize uint32 `json:"page_size"`
	Total    uint32 `json:"total"`
}

type PageResponse_builder struct {
	Page     *uint32
	PageSize *uint32
	Total    *uint32
}

func (b PageResponse_builder) Build() *PageResponse {
	x := &PageResponse{}
	if b.Page != nil {
		x.Page = *b.Page
	}
	if b.PageSize != nil {
		x.PageSize = *b.PageSize
	}
	if b.Total != nil {
		x.Total = *b.Total
	}
	return x
}

type ListItem struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Source     string `json:"source"`
	ItemCount  uint32 `json:"item_count"`
	ErrorCount uint32 `json:"error_count"`
	Preview    string `json:"preview"`
}

type ListItem_builder struct {
	Name       *string
	Type       *string
	Source     *string
	ItemCount  *uint32
	ErrorCount *uint32
	Preview    *string
}

func (b ListItem_builder) Build() *ListItem {
	x := &ListItem{}
	if b.Name != nil {
		x.Name = *b.Name
	}
	if b.Type != nil {
		x.Type = *b.Type
	}
	if b.Source != nil {
		x.Source = *b.Source
	}
	if b.ItemCount != nil {
		x.ItemCount = *b.ItemCount
	}
	if b.ErrorCount != nil {
		x.ErrorCount = *b.ErrorCount
	}
	if b.Preview != nil {
		x.Preview = *b.Preview
	}
	return x
}

func (x *ListItem) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

func (x *ListItem) GetType() string {
	if x == nil {
		return ""
	}
	return x.Type
}

func (x *ListItem) GetSource() string {
	if x == nil {
		return ""
	}
	return x.Source
}

func (x *ListItem) GetPreview() string {
	if x == nil {
		return ""
	}
	return x.Preview
}

type ListResponse struct {
	Names          []string                     `json:"names"`
	MaxminddbGeoip *schemaconfig.MaxminddbGeoip `json:"maxminddb_geoip"`
	RefreshConfig  *schemaconfig.RefreshConfig  `json:"refresh_config"`
	Page           *PageResponse                `json:"page"`
	Items          []*ListItem                  `json:"items"`
}

func (x *ListResponse) GetNames() []string {
	if x == nil {
		return nil
	}
	return x.Names
}

func (x *ListResponse) SetNames(v []string) { x.Names = v }

func (x *ListResponse) GetMaxminddbGeoip() *schemaconfig.MaxminddbGeoip {
	if x == nil {
		return nil
	}
	return x.MaxminddbGeoip
}

func (x *ListResponse) SetMaxminddbGeoip(v *schemaconfig.MaxminddbGeoip) { x.MaxminddbGeoip = v }

func (x *ListResponse) GetRefreshConfig() *schemaconfig.RefreshConfig {
	if x == nil {
		return nil
	}
	return x.RefreshConfig
}

func (x *ListResponse) SetRefreshConfig(v *schemaconfig.RefreshConfig) { x.RefreshConfig = v }

func (x *ListResponse) GetItems() []*ListItem {
	if x == nil {
		return nil
	}
	return x.Items
}

func (x *ListResponse) SetItems(v []*ListItem)  { x.Items = v }
func (x *ListResponse) SetPage(v *PageResponse) { x.Page = v }

func (x *ListResponse) MarshalJSON() ([]byte, error) {
	type out struct {
		Names          []string       `json:"names"`
		MaxminddbGeoip jsontext.Value `json:"maxminddb_geoip"`
		RefreshConfig  jsontext.Value `json:"refresh_config"`
		Page           *PageResponse  `json:"page"`
		Items          []*ListItem    `json:"items"`
	}
	maxminddbGeoip, err := marshalJSONRaw(x.GetMaxminddbGeoip())
	if err != nil {
		return nil, err
	}
	refreshConfig, err := marshalJSONRaw(x.GetRefreshConfig())
	if err != nil {
		return nil, err
	}
	return json.Marshal(out{
		Names:          x.GetNames(),
		MaxminddbGeoip: maxminddbGeoip,
		RefreshConfig:  refreshConfig,
		Page:           x.Page,
		Items:          x.GetItems(),
	})
}

type SaveListConfigRequest struct {
	MaxminddbGeoip  *schemaconfig.MaxminddbGeoip `json:"maxminddb_geoip"`
	RefreshInterval uint64                       `json:"refresh_interval"`
}

func (x *SaveListConfigRequest) GetMaxminddbGeoip() *schemaconfig.MaxminddbGeoip {
	if x == nil {
		return nil
	}
	return x.MaxminddbGeoip
}

func (x *SaveListConfigRequest) GetRefreshInterval() uint64 {
	if x == nil {
		return 0
	}
	return x.RefreshInterval
}

func (x *SaveListConfigRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	x.RefreshInterval = uint64FromJSON(raw, "refresh_interval", "refreshInterval")
	x.MaxminddbGeoip = &schemaconfig.MaxminddbGeoip{}
	if err := unmarshalJSONRaw(rawValue(raw, "maxminddb_geoip", "maxminddbGeoip"), x.MaxminddbGeoip); err != nil {
		return err
	}
	return nil
}

type RuleItem struct {
	Name      string `json:"name"`
	Disabled  bool   `json:"disabled"`
	Index     uint32 `json:"index"`
	Mode      string `json:"mode"`
	Tag       string `json:"tag"`
	Resolver  string `json:"resolver"`
	RuleCount uint32 `json:"rule_count"`
}

type RuleItem_builder struct {
	Name      *string
	Disabled  *bool
	Index     *uint32
	Mode      *string
	Tag       *string
	Resolver  *string
	RuleCount *uint32
}

func (b RuleItem_builder) Build() *RuleItem {
	x := &RuleItem{}
	if b.Name != nil {
		x.Name = *b.Name
	}
	if b.Disabled != nil {
		x.Disabled = *b.Disabled
	}
	if b.Index != nil {
		x.Index = *b.Index
	}
	if b.Mode != nil {
		x.Mode = *b.Mode
	}
	if b.Tag != nil {
		x.Tag = *b.Tag
	}
	if b.Resolver != nil {
		x.Resolver = *b.Resolver
	}
	if b.RuleCount != nil {
		x.RuleCount = *b.RuleCount
	}
	return x
}

func (x *RuleItem) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

func (x *RuleItem) GetDisabled() bool {
	if x == nil {
		return false
	}
	return x.Disabled
}

type RuleResponse struct {
	Names []string      `json:"names"`
	Items []*RuleItem   `json:"items"`
	Page  *PageResponse `json:"page"`
}

type RuleResponse_builder struct {
	Names []string
	Items []*RuleItem
	Page  *PageResponse
}

func (b RuleResponse_builder) Build() *RuleResponse {
	return &RuleResponse{Names: b.Names, Items: b.Items, Page: b.Page}
}

func (x *RuleResponse) GetNames() []string {
	if x == nil {
		return nil
	}
	return x.Names
}

func (x *RuleResponse) GetItems() []*RuleItem {
	if x == nil {
		return nil
	}
	return x.Items
}

func (x *RuleResponse) SetNames(v []string)     { x.Names = v }
func (x *RuleResponse) SetItems(v []*RuleItem)  { x.Items = v }
func (x *RuleResponse) SetPage(v *PageResponse) { x.Page = v }

type RuleIndex struct {
	Index uint32 `json:"index"`
	Name  string `json:"name"`
}

type RuleIndex_builder struct {
	Index *uint32
	Name  *string
}

func (b RuleIndex_builder) Build() *RuleIndex {
	x := &RuleIndex{}
	if b.Index != nil {
		x.Index = *b.Index
	}
	if b.Name != nil {
		x.Name = *b.Name
	}
	return x
}

func (x *RuleIndex) GetIndex() uint32 {
	if x == nil {
		return 0
	}
	return x.Index
}

func (x *RuleIndex) SetIndex(v uint32) { x.Index = v }

func (x *RuleIndex) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

func (x *RuleIndex) SetName(v string) { x.Name = v }

type RuleSaveRequest struct {
	Index *RuleIndex           `json:"index"`
	Rule  *schemaconfig.Rulev2 `json:"rule"`
}

func (x *RuleSaveRequest) GetIndex() *RuleIndex {
	if x == nil {
		return nil
	}
	return x.Index
}

func (x *RuleSaveRequest) GetRule() *schemaconfig.Rulev2 {
	if x == nil {
		return nil
	}
	return x.Rule
}

func (x *RuleSaveRequest) SetIndex(v *RuleIndex)          { x.Index = v }
func (x *RuleSaveRequest) SetRule(v *schemaconfig.Rulev2) { x.Rule = v }

func (x *RuleSaveRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if v := rawValue(raw, "index"); len(v) != 0 {
		x.Index = &RuleIndex{}
		if err := json.Unmarshal(v, x.Index); err != nil {
			return err
		}
	}
	x.Rule = &schemaconfig.Rulev2{}
	return unmarshalJSONRaw(rawValue(raw, "rule"), x.Rule)
}

type ChangePriorityRequestChangePriorityOperate int32

const (
	ChangePriorityRequest_Exchange     ChangePriorityRequestChangePriorityOperate = 0
	ChangePriorityRequest_InsertBefore ChangePriorityRequestChangePriorityOperate = 1
	ChangePriorityRequest_InsertAfter  ChangePriorityRequestChangePriorityOperate = 2
)

func (x ChangePriorityRequestChangePriorityOperate) Enum() *ChangePriorityRequestChangePriorityOperate {
	return &x
}

type ChangePriorityRequest struct {
	Source  *RuleIndex                                 `json:"source"`
	Target  *RuleIndex                                 `json:"target"`
	Operate ChangePriorityRequestChangePriorityOperate `json:"operate"`
}

type ChangePriorityRequest_builder struct {
	Source  *RuleIndex
	Target  *RuleIndex
	Operate *ChangePriorityRequestChangePriorityOperate
}

func (b ChangePriorityRequest_builder) Build() *ChangePriorityRequest {
	x := &ChangePriorityRequest{Source: b.Source, Target: b.Target}
	if b.Operate != nil {
		x.Operate = *b.Operate
	}
	return x
}

func (x *ChangePriorityRequest) GetSource() *RuleIndex {
	if x == nil {
		return nil
	}
	return x.Source
}

func (x *ChangePriorityRequest) GetTarget() *RuleIndex {
	if x == nil {
		return nil
	}
	return x.Target
}

func (x *ChangePriorityRequest) GetOperate() ChangePriorityRequestChangePriorityOperate {
	if x == nil {
		return ChangePriorityRequest_Exchange
	}
	return x.Operate
}

type TestResponse struct {
	Mode        *schemaconfig.ModeConfig             `json:"mode"`
	AfterAddr   string                               `json:"after_addr"`
	MatchResult []*schemastatistic.MatchHistoryEntry `json:"match_result"`
	Lists       []string                             `json:"lists"`
	Ips         []string                             `json:"ips"`
}

type TestResponse_builder struct {
	Mode        *schemaconfig.ModeConfig
	AfterAddr   *string
	MatchResult []*schemastatistic.MatchHistoryEntry
	Lists       []string
	Ips         []string
}

func (b TestResponse_builder) Build() *TestResponse {
	x := &TestResponse{Mode: b.Mode, MatchResult: b.MatchResult, Lists: b.Lists, Ips: b.Ips}
	if b.AfterAddr != nil {
		x.AfterAddr = *b.AfterAddr
	}
	return x
}

func (x *TestResponse) MarshalJSON() ([]byte, error) {
	mode, err := marshalJSONRaw(x.Mode)
	if err != nil {
		return nil, err
	}
	matchResult, err := marshalJSONRawSlice(x.MatchResult)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Mode        jsontext.Value   `json:"mode"`
		AfterAddr   string           `json:"after_addr"`
		MatchResult []jsontext.Value `json:"match_result"`
		Lists       []string         `json:"lists"`
		Ips         []string         `json:"ips"`
	}{mode, x.AfterAddr, matchResult, x.Lists, x.Ips})
}

type BlockHistory struct {
	Protocol   string    `json:"protocol"`
	Host       string    `json:"host"`
	Time       time.Time `json:"time"`
	Process    string    `json:"process"`
	BlockCount uint64    `json:"block_count"`
}

type BlockHistory_builder struct {
	Protocol   *string
	Host       *string
	Time       time.Time
	Process    *string
	BlockCount *uint64
}

func (b BlockHistory_builder) Build() *BlockHistory {
	x := &BlockHistory{Time: b.Time}
	if b.Protocol != nil {
		x.Protocol = *b.Protocol
	}
	if b.Host != nil {
		x.Host = *b.Host
	}
	if b.Process != nil {
		x.Process = *b.Process
	}
	if b.BlockCount != nil {
		x.BlockCount = *b.BlockCount
	}
	return x
}

func (x *BlockHistory) GetProcess() string {
	if x == nil {
		return ""
	}
	return x.Process
}

func (x *BlockHistory) GetBlockCount() uint64 {
	if x == nil {
		return 0
	}
	return x.BlockCount
}

func (x *BlockHistory) SetTime(v time.Time)    { x.Time = v }
func (x *BlockHistory) SetBlockCount(v uint64) { x.BlockCount = v }

type BlockHistoryList struct {
	Objects            []*BlockHistory `json:"objects"`
	DumpProcessEnabled bool            `json:"dump_process_enabled"`
}

type BlockHistoryList_builder struct {
	Objects            []*BlockHistory
	DumpProcessEnabled *bool
}

func (b BlockHistoryList_builder) Build() *BlockHistoryList {
	x := &BlockHistoryList{Objects: b.Objects}
	if b.DumpProcessEnabled != nil {
		x.DumpProcessEnabled = *b.DumpProcessEnabled
	}
	return x
}

type InboundItem struct {
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Network    string   `json:"network"`
	Listen     string   `json:"listen"`
	Protocol   string   `json:"protocol"`
	Transports []string `json:"transports"`
}

type InboundItem_builder struct {
	Name       *string
	Enabled    *bool
	Network    *string
	Listen     *string
	Protocol   *string
	Transports []string
}

func (b InboundItem_builder) Build() *InboundItem {
	x := &InboundItem{Transports: b.Transports}
	if b.Name != nil {
		x.Name = *b.Name
	}
	if b.Enabled != nil {
		x.Enabled = *b.Enabled
	}
	if b.Network != nil {
		x.Network = *b.Network
	}
	if b.Listen != nil {
		x.Listen = *b.Listen
	}
	if b.Protocol != nil {
		x.Protocol = *b.Protocol
	}
	return x
}

func (x *InboundItem) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

func (x *InboundItem) GetNetwork() string {
	if x == nil {
		return ""
	}
	return x.Network
}

func (x *InboundItem) GetListen() string {
	if x == nil {
		return ""
	}
	return x.Listen
}

func (x *InboundItem) GetProtocol() string {
	if x == nil {
		return ""
	}
	return x.Protocol
}

type InboundsResponse struct {
	Names           []string            `json:"names"`
	HijackDns       bool                `json:"hijack_dns"`
	HijackDnsFakeip bool                `json:"hijack_dns_fakeip"`
	Sniff           *schemaconfig.Sniff `json:"sniff"`
	Page            *PageResponse       `json:"page"`
	Items           []*InboundItem      `json:"items"`
}

func (x *InboundsResponse) GetHijackDns() bool {
	if x == nil {
		return false
	}
	return x.HijackDns
}

func (x *InboundsResponse) SetHijackDns(v bool) { x.HijackDns = v }

func (x *InboundsResponse) GetHijackDnsFakeip() bool {
	if x == nil {
		return false
	}
	return x.HijackDnsFakeip
}

func (x *InboundsResponse) SetHijackDnsFakeip(v bool) { x.HijackDnsFakeip = v }

func (x *InboundsResponse) GetSniff() *schemaconfig.Sniff {
	if x == nil {
		return nil
	}
	return x.Sniff
}

func (x *InboundsResponse) SetSniff(v *schemaconfig.Sniff) { x.Sniff = v }
func (x *InboundsResponse) SetNames(v []string)            { x.Names = v }

func (x *InboundsResponse) GetItems() []*InboundItem {
	if x == nil {
		return nil
	}
	return x.Items
}

func (x *InboundsResponse) SetItems(v []*InboundItem) { x.Items = v }
func (x *InboundsResponse) SetPage(v *PageResponse)   { x.Page = v }

func (x *InboundsResponse) MarshalJSON() ([]byte, error) {
	sniff, err := marshalJSONRaw(x.GetSniff())
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Names           []string       `json:"names"`
		HijackDns       bool           `json:"hijack_dns"`
		HijackDnsFakeip bool           `json:"hijack_dns_fakeip"`
		Sniff           jsontext.Value `json:"sniff"`
		Page            *PageResponse  `json:"page"`
		Items           []*InboundItem `json:"items"`
	}{x.Names, x.HijackDns, x.HijackDnsFakeip, sniff, x.Page, x.Items})
}

func (x *InboundsResponse) UnmarshalJSON(b []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	_ = json.Unmarshal(rawValue(raw, "names"), &x.Names)
	x.HijackDns = boolFromJSON(raw, "hijack_dns", "hijackDns")
	x.HijackDnsFakeip = boolFromJSON(raw, "hijack_dns_fakeip", "hijackDnsFakeip")
	x.Sniff = &schemaconfig.Sniff{}
	return unmarshalJSONRaw(rawValue(raw, "sniff"), x.Sniff)
}

type PlatformInfoResponsePlatformDarwin struct {
	NetworkServices []string `json:"network_services"`
}

type PlatformInfoResponsePlatformDarwin_builder struct {
	NetworkServices []string
}

func (b PlatformInfoResponsePlatformDarwin_builder) Build() *PlatformInfoResponsePlatformDarwin {
	return &PlatformInfoResponsePlatformDarwin{NetworkServices: b.NetworkServices}
}

type PlatformInfoResponse struct {
	Darwin *PlatformInfoResponsePlatformDarwin `json:"darwin"`
}

func (x *PlatformInfoResponse) SetDarwin(v *PlatformInfoResponsePlatformDarwin) { x.Darwin = v }

type ResolveList struct {
	Names []string        `json:"names"`
	Page  *PageResponse   `json:"page"`
	Items []*ResolverItem `json:"items"`
}

func (x *ResolveList) GetNames() []string {
	if x == nil {
		return nil
	}
	return x.Names
}

func (x *ResolveList) SetNames(v []string) { x.Names = v }

func (x *ResolveList) GetItems() []*ResolverItem {
	if x == nil {
		return nil
	}
	return x.Items
}

func (x *ResolveList) SetItems(v []*ResolverItem) { x.Items = v }
func (x *ResolveList) SetPage(v *PageResponse)    { x.Page = v }

type ResolverItem struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	Subnet        string `json:"subnet"`
	TlsServername string `json:"tls_servername"`
	System        bool   `json:"system"`
}

type ResolverItem_builder struct {
	Name          *string
	Type          *string
	Host          *string
	Subnet        *string
	TlsServername *string
	System        *bool
}

func (b ResolverItem_builder) Build() *ResolverItem {
	x := &ResolverItem{}
	if b.Name != nil {
		x.Name = *b.Name
	}
	if b.Type != nil {
		x.Type = *b.Type
	}
	if b.Host != nil {
		x.Host = *b.Host
	}
	if b.Subnet != nil {
		x.Subnet = *b.Subnet
	}
	if b.TlsServername != nil {
		x.TlsServername = *b.TlsServername
	}
	if b.System != nil {
		x.System = *b.System
	}
	return x
}

func (x *ResolverItem) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

func (x *ResolverItem) GetType() string {
	if x == nil {
		return ""
	}
	return x.Type
}

func (x *ResolverItem) GetHost() string {
	if x == nil {
		return ""
	}
	return x.Host
}

type SaveResolver struct {
	Name     string            `json:"name"`
	Resolver *schemaconfig.Dns `json:"resolver"`
}

func (x *SaveResolver) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

func (x *SaveResolver) GetResolver() *schemaconfig.Dns {
	if x == nil {
		return nil
	}
	return x.Resolver
}

func (x *SaveResolver) SetName(v string)                { x.Name = v }
func (x *SaveResolver) SetResolver(v *schemaconfig.Dns) { x.Resolver = v }

func (x *SaveResolver) UnmarshalJSON(b []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	x.Name = stringFromJSON(raw, "name")
	x.Resolver = &schemaconfig.Dns{}
	return unmarshalJSONRaw(rawValue(raw, "resolver"), x.Resolver)
}

type Hosts struct {
	Hosts map[string]string `json:"hosts"`
}

type Hosts_builder struct {
	Hosts map[string]string
}

func (b Hosts_builder) Build() *Hosts { return &Hosts{Hosts: b.Hosts} }

func (x *Hosts) GetHosts() map[string]string {
	if x == nil {
		return nil
	}
	return x.Hosts
}

type NowResp struct {
	Tcp *schemanode.Point `json:"tcp"`
	Udp *schemanode.Point `json:"udp"`
}

type NowResp_builder struct {
	Tcp *schemanode.Point
	Udp *schemanode.Point
}

func (b NowResp_builder) Build() *NowResp { return &NowResp{Tcp: b.Tcp, Udp: b.Udp} }

func (x *NowResp) MarshalJSON() ([]byte, error) {
	tcp, err := marshalJSONRaw(x.Tcp)
	if err != nil {
		return nil, err
	}
	udp, err := marshalJSONRaw(x.Udp)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Tcp jsontext.Value `json:"tcp"`
		Udp jsontext.Value `json:"udp"`
	}{tcp, udp})
}

type UseReq struct {
	Hash string `json:"hash"`
}

type UseReq_builder struct {
	Hash *string
}

func (b UseReq_builder) Build() *UseReq {
	x := &UseReq{}
	if b.Hash != nil {
		x.Hash = *b.Hash
	}
	return x
}

func (x *UseReq) GetHash() string {
	if x == nil {
		return ""
	}
	return x.Hash
}

func (x *UseReq) SetHash(v string) { x.Hash = v }

type NodesResponse_Node struct {
	Hash string `json:"hash"`
	Name string `json:"name"`
}

type NodesResponse_Node_builder struct {
	Hash *string
	Name *string
}

func (b NodesResponse_Node_builder) Build() *NodesResponse_Node {
	x := &NodesResponse_Node{}
	if b.Hash != nil {
		x.Hash = *b.Hash
	}
	if b.Name != nil {
		x.Name = *b.Name
	}
	return x
}

func (x *NodesResponse_Node) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

type NodesResponse_Group struct {
	Name  string                `json:"name"`
	Nodes []*NodesResponse_Node `json:"nodes"`
}

type NodesResponse_Group_builder struct {
	Name  *string
	Nodes []*NodesResponse_Node
}

func (b NodesResponse_Group_builder) Build() *NodesResponse_Group {
	x := &NodesResponse_Group{Nodes: b.Nodes}
	if b.Name != nil {
		x.Name = *b.Name
	}
	return x
}

func (x *NodesResponse_Group) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

type NodesResponse struct {
	Groups []*NodesResponse_Group `json:"groups"`
}

type NodesResponse_builder struct {
	Groups []*NodesResponse_Group
}

func (b NodesResponse_builder) Build() *NodesResponse { return &NodesResponse{Groups: b.Groups} }

type ActivatesResponse struct {
	Nodes []*schemanode.Point `json:"nodes"`
}

type ActivatesResponse_builder struct {
	Nodes []*schemanode.Point
}

func (b ActivatesResponse_builder) Build() *ActivatesResponse {
	return &ActivatesResponse{Nodes: b.Nodes}
}

func (x *ActivatesResponse) MarshalJSON() ([]byte, error) {
	nodes, err := marshalJSONRawSlice(x.Nodes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Nodes []jsontext.Value `json:"nodes"`
	}{nodes})
}

type SaveLinkReq struct {
	Links []*schemanode.Link `json:"links"`
}

func (x *SaveLinkReq) GetLinks() []*schemanode.Link {
	if x == nil {
		return nil
	}
	return x.Links
}

func (x *SaveLinkReq) UnmarshalJSON(b []byte) error {
	return unmarshalJSONSliceField(b, "links", func() *schemanode.Link { return &schemanode.Link{} }, func(values []*schemanode.Link) { x.Links = values })
}

type LinkReq struct {
	Names []string `json:"names"`
}

func (x *LinkReq) GetNames() []string {
	if x == nil {
		return nil
	}
	return x.Names
}

type GetLinksResp struct {
	Links map[string]*schemanode.Link `json:"links"`
}

type GetLinksResp_builder struct {
	Links map[string]*schemanode.Link
}

func (b GetLinksResp_builder) Build() *GetLinksResp { return &GetLinksResp{Links: b.Links} }

func (x *GetLinksResp) MarshalJSON() ([]byte, error) {
	links, err := marshalJSONRawMap(x.Links)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Links map[string]jsontext.Value `json:"links"`
	}{links})
}

type SavePublishRequest struct {
	Name    string              `json:"name"`
	Publish *schemanode.Publish `json:"publish"`
}

func (x *SavePublishRequest) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

func (x *SavePublishRequest) GetPublish() *schemanode.Publish {
	if x == nil {
		return nil
	}
	return x.Publish
}

func (x *SavePublishRequest) SetName(v string)                 { x.Name = v }
func (x *SavePublishRequest) SetPublish(v *schemanode.Publish) { x.Publish = v }

func (x *SavePublishRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	x.Name = stringFromJSON(raw, "name")
	x.Publish = &schemanode.Publish{}
	return unmarshalJSONRaw(rawValue(raw, "publish"), x.Publish)
}

type ListPublishResponse struct {
	Publishes map[string]*schemanode.Publish `json:"publishes"`
}

type ListPublishResponse_builder struct {
	Publishes map[string]*schemanode.Publish
}

func (b ListPublishResponse_builder) Build() *ListPublishResponse {
	return &ListPublishResponse{Publishes: b.Publishes}
}

func (x *ListPublishResponse) MarshalJSON() ([]byte, error) {
	publishes, err := marshalJSONRawMap(x.Publishes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Publishes map[string]jsontext.Value `json:"publishes"`
	}{publishes})
}

type PublishRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Path     string `json:"path"`
}

func (x *PublishRequest) GetName() string {
	if x == nil {
		return ""
	}
	return x.Name
}

func (x *PublishRequest) GetPassword() string {
	if x == nil {
		return ""
	}
	return x.Password
}

func (x *PublishRequest) GetPath() string {
	if x == nil {
		return ""
	}
	return x.Path
}

func (x *PublishRequest) SetName(v string)     { x.Name = v }
func (x *PublishRequest) SetPassword(v string) { x.Password = v }
func (x *PublishRequest) SetPath(v string)     { x.Path = v }

type PublishResponse struct {
	Points []*schemanode.Point `json:"points"`
}

type PublishResponse_builder struct {
	Points []*schemanode.Point
}

func (b PublishResponse_builder) Build() *PublishResponse { return &PublishResponse{Points: b.Points} }

func (x *PublishResponse) GetPoints() []*schemanode.Point {
	if x == nil {
		return nil
	}
	return x.Points
}

func (x *PublishResponse) MarshalJSON() ([]byte, error) {
	points, err := marshalJSONRawSlice(x.Points)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Points []jsontext.Value `json:"points"`
	}{points})
}

func (x *PublishResponse) UnmarshalJSON(b []byte) error {
	return unmarshalJSONSliceField(b, "points", func() *schemanode.Point { return &schemanode.Point{} }, func(values []*schemanode.Point) { x.Points = values })
}

type SaveTagReq struct {
	Tag  string             `json:"tag"`
	Type schemanode.TagType `json:"type"`
	Hash string             `json:"hash"`
}

func (x *SaveTagReq) GetTag() string {
	if x == nil {
		return ""
	}
	return x.Tag
}

func (x *SaveTagReq) GetType() schemanode.TagType {
	if x == nil {
		return schemanode.TagType_node
	}
	return x.Type
}

func (x *SaveTagReq) GetHash() string {
	if x == nil {
		return ""
	}
	return x.Hash
}

func (x *SaveTagReq) SetTag(v string) { x.Tag = v }

type TagsResponse struct {
	Tags  map[string]*schemanode.Tags `json:"tags"`
	Items []*TagItem                  `json:"items"`
	Page  *TagPage                    `json:"page"`
}

type TagsResponse_builder struct {
	Tags  map[string]*schemanode.Tags
	Items []*TagItem
	Page  *TagPage
}

func (b TagsResponse_builder) Build() *TagsResponse {
	return &TagsResponse{Tags: b.Tags, Items: b.Items, Page: b.Page}
}

func (x *TagsResponse) GetTags() map[string]*schemanode.Tags {
	if x == nil {
		return nil
	}
	return x.Tags
}

func (x *TagsResponse) SetTags(v map[string]*schemanode.Tags) { x.Tags = v }
func (x *TagsResponse) SetItems(v []*TagItem)                 { x.Items = v }
func (x *TagsResponse) SetPage(v *TagPage)                    { x.Page = v }

func (x *TagsResponse) MarshalJSON() ([]byte, error) {
	tags, err := marshalJSONRawMap(x.Tags)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Tags  map[string]jsontext.Value `json:"tags"`
		Items []*TagItem                `json:"items"`
		Page  *TagPage                  `json:"page"`
	}{tags, x.Items, x.Page})
}

type TagItem struct {
	Name string           `json:"name"`
	Tag  *schemanode.Tags `json:"tag"`
}

type TagItem_builder struct {
	Name *string
	Tag  *schemanode.Tags
}

func (b TagItem_builder) Build() *TagItem {
	x := &TagItem{Tag: b.Tag}
	if b.Name != nil {
		x.Name = *b.Name
	}
	return x
}

func (x *TagItem) MarshalJSON() ([]byte, error) {
	tag, err := marshalJSONRaw(x.Tag)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Name string         `json:"name"`
		Tag  jsontext.Value `json:"tag"`
	}{x.Name, tag})
}

type TagPageRequest struct {
	Page     uint32 `json:"page"`
	PageSize uint32 `json:"page_size"`
	Query    string `json:"query"`
}

func (x *TagPageRequest) GetPage() uint32 {
	if x == nil {
		return 0
	}
	return x.Page
}

func (x *TagPageRequest) SetPage(v uint32) { x.Page = v }

func (x *TagPageRequest) GetPageSize() uint32 {
	if x == nil {
		return 0
	}
	return x.PageSize
}

func (x *TagPageRequest) SetPageSize(v uint32) { x.PageSize = v }

func (x *TagPageRequest) GetQuery() string {
	if x == nil {
		return ""
	}
	return x.Query
}

func (x *TagPageRequest) SetQuery(v string) { x.Query = v }

type TagPage struct {
	Page     uint32 `json:"page"`
	PageSize uint32 `json:"page_size"`
	Total    uint32 `json:"total"`
}

type TagPage_builder struct {
	Page     *uint32
	PageSize *uint32
	Total    *uint32
}

func (b TagPage_builder) Build() *TagPage {
	x := &TagPage{}
	if b.Page != nil {
		x.Page = *b.Page
	}
	if b.PageSize != nil {
		x.PageSize = *b.PageSize
	}
	if b.Total != nil {
		x.Total = *b.Total
	}
	return x
}

func marshalJSONRawMap[T any](items map[string]T) (map[string]jsontext.Value, error) {
	out := make(map[string]jsontext.Value, len(items))
	for key, item := range items {
		b, err := marshalJSONRaw(item)
		if err != nil {
			return nil, err
		}
		out[key] = b
	}
	return out, nil
}

func unmarshalJSONRaw(data jsontext.Value, msg any) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	return json.Unmarshal(data, msg)
}

func rawValue(raw map[string]jsontext.Value, names ...string) jsontext.Value {
	for _, name := range names {
		if v, ok := raw[name]; ok {
			return v
		}
	}
	return nil
}

func stringFromJSON(raw map[string]jsontext.Value, names ...string) string {
	var out string
	_ = json.Unmarshal(rawValue(raw, names...), &out)
	return out
}

func boolFromJSON(raw map[string]jsontext.Value, names ...string) bool {
	var out bool
	_ = json.Unmarshal(rawValue(raw, names...), &out)
	return out
}

func uint64FromJSON(raw map[string]jsontext.Value, names ...string) uint64 {
	value := rawValue(raw, names...)
	var number uint64
	if err := json.Unmarshal(value, &number); err == nil {
		return number
	}
	var str string
	if err := json.Unmarshal(value, &str); err == nil && str != "" {
		if n, err := strconv.ParseUint(str, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func unmarshalJSONSliceField[T any](b []byte, field string, newItem func() T, set func([]T)) error {
	var raw map[string][]jsontext.Value
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	values := make([]T, 0, len(raw[field]))
	for _, item := range raw[field] {
		msg := newItem()
		if err := unmarshalJSONRaw(item, msg); err != nil {
			return err
		}
		values = append(values, msg)
	}
	set(values)
	return nil
}
