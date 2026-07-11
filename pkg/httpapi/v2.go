package httpapi

import (
	"context"
	"strings"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	contractupdate "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type SettingsController interface {
	Info(context.Context) (contractsettings.Info, error)
	Load(context.Context) (contractsettings.Settings, error)
	Save(context.Context, contractsettings.Settings) (contractsettings.Settings, error)
}
type BackupController interface {
	Get(context.Context) (contractbackup.Option, error)
	Save(context.Context, contractbackup.Option) (contractbackup.Option, error)
	Run(context.Context) error
	Restore(context.Context, contractbackup.RestoreOption) error
}
type ToolsController interface {
	Interfaces(context.Context) (contracttools.Interfaces, error)
	Licenses(context.Context) (contracttools.Licenses, error)
	TailLogs(context.Context, func(contracttools.LogBatch) error) error
}
type UpdateController interface {
	Check(context.Context, string) (contractupdate.CheckResult, error)
	Apply(context.Context, contractupdate.ApplyRequest) error
	Status(context.Context) contractupdate.Status
}
type ConnectionMonitor interface {
	Total(context.Context) (contractconnection.TotalFlow, error)
	Traffic(context.Context, string, time.Time, time.Time) (contractconnection.TrafficSeries, error)
	Telemetry(context.Context, time.Time, time.Time, int) (contractconnection.TelemetrySummary, error)
	List(context.Context) (contractconnection.Connections, error)
	Close(context.Context, []uint64) error
	FailedHistory(context.Context) (contractconnection.FailedHistoryList, error)
	AllHistory(context.Context) (contractconnection.AllHistoryList, error)
	Events(context.Context, func(contractconnection.Event) error) error
}
type ResolverConfigController interface {
	Hosts(context.Context) (contractresolver.Hosts, error)
	SaveHosts(context.Context, contractresolver.Hosts) (contractresolver.Hosts, error)
	FakeDNS(context.Context) (contractresolver.FakeDNS, error)
	SaveFakeDNS(context.Context, contractresolver.FakeDNS) (contractresolver.FakeDNS, error)
	Server(context.Context) (contractresolver.Server, error)
	SaveServer(context.Context, contractresolver.Server) (contractresolver.Server, error)
}
type ResolverController interface {
	Save(context.Context, contractresolver.Resolver) (contractresolver.Resolver, error)
	Remove(context.Context, string) error
}
type NodeController interface {
	Selected(context.Context) (contractnode.Selection, error)
	Active(context.Context) ([]contractnode.Node, error)
	Save(context.Context, contractnode.Node) (contractnode.Node, error)
	Remove(context.Context, string) error
	Use(context.Context, string) error
	Close(context.Context, string) error
	Latency(context.Context, string, contractnode.LatencyRequest) (contractnode.LatencyResponse, error)
}
type SubscriptionController interface {
	Update(context.Context, []string) error
	ResolvePublish(context.Context, string, contractsubscription.ResolvePublishRequest) (contractsubscription.ResolvePublishResponse, error)
}
type RouteRuntimeController interface {
	SaveConfig(context.Context, contractroute.Config) error
	ScheduleApply()
	Apply(context.Context) error
	ActivationStatus(context.Context) (contractroute.RuleActivationStatus, error)
	Test(context.Context, string) (contractroute.RuleTestResponse, error)
	BlockHistory(context.Context) (contractroute.BlockHistoryList, error)
}
type ListRuntimeController interface {
	SaveConfig(context.Context, contractroute.ListConfig, uint64) error
	Refresh(context.Context) error
	ApplyChanges(context.Context) error
	Apply(context.Context) error
	ActivationStatus(context.Context) (contractroute.ListActivationStatus, error)
}
type InboundStore interface {
	List(context.Context) ([]contractinbound.Inbound, error)
	Get(context.Context, string) (contractinbound.Inbound, error)
	Save(context.Context, contractinbound.Inbound, int64) error
	Delete(context.Context, string) error
	Settings(context.Context) (plainstore.InboundSettings, error)
	SaveSettings(context.Context, plainstore.InboundSettings) error
}
type V2Services struct {
	Settings       SettingsController
	Inbounds       InboundStore
	Nodes          *plainstore.NodeStore
	Node           NodeController
	Subscriptions  *plainstore.SubscriptionStore
	Resolvers      *plainstore.ResolverStore
	Resolver       ResolverController
	ResolverConfig ResolverConfigController
	Connections    ConnectionMonitor
	Tools          ToolsController
	Update         UpdateController
	Backup         BackupController
	Lists          ListRuntimeController
	RouteSettings  *plainstore.RouteSettingsStore
	RouteLists     *plainstore.RouteListStore
	Rules          RouteRuntimeController
	RouteRules     *plainstore.RouteRuleStore
	RouteTags      *plainstore.RouteTagStore
	Subscribe      SubscriptionController
}
type pageV2 struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
	Total    int `json:"total"`
}
type listV2[T any] struct {
	Items []T    `json:"items"`
	Page  pageV2 `json:"page"`
}
type inboundConfigV2 struct {
	HijackDNS       bool `json:"hijackDns"`
	HijackDNSFakeIP bool `json:"hijackDnsFakeIp"`
	Sniff           bool `json:"sniff"`
}

func RegisterV2(register RegisterFunc, services V2Services) {
	handlers := newV2Handlers(services)
	for _, route := range v2Routes {
		register(v2RoutePattern(route), handlers.handler(route.endpoint))
	}
}
func defaultInboundConfigV2() inboundConfigV2 {
	return inboundConfigV2{HijackDNS: true, HijackDNSFakeIP: true, Sniff: true}
}
func inboundConfigFromStoreV2(config plainstore.InboundSettings) inboundConfigV2 {
	return inboundConfigV2{HijackDNS: config.HijackDNS, HijackDNSFakeIP: config.HijackDNSFakeIP, Sniff: config.Sniff}
}
func inboundConfigToStoreV2(config inboundConfigV2) plainstore.InboundSettings {
	return plainstore.InboundSettings{HijackDNS: config.HijackDNS, HijackDNSFakeIP: config.HijackDNSFakeIP, Sniff: config.Sniff}
}
func filterInbounds(items []contractinbound.Inbound, query string) []contractinbound.Inbound {
	query = strings.ToLower(query)
	out := make([]contractinbound.Inbound, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.ID), query) || strings.Contains(strings.ToLower(item.Name), query) || strings.Contains(strings.ToLower(item.Network.Type), query) || strings.Contains(strings.ToLower(item.Protocol.Type), query) {
			out = append(out, item)
		}
	}
	return out
}
func filterNodes(items []contractnode.Node, query string) []contractnode.Node {
	query = strings.ToLower(query)
	out := make([]contractnode.Node, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.ID), query) || strings.Contains(strings.ToLower(item.Name), query) || strings.Contains(strings.ToLower(item.Group), query) || strings.Contains(strings.ToLower(item.Origin), query) || nodeChainContains(item, query) {
			out = append(out, item)
		}
	}
	return out
}
func nodeChainContains(item contractnode.Node, query string) bool {
	for _, protocol := range item.Chain {
		if strings.Contains(strings.ToLower(protocol.Type), query) {
			return true
		}
	}
	return false
}
func filterResolvers(items []contractresolver.Resolver, query string) []contractresolver.Resolver {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return items
	}
	out := make([]contractresolver.Resolver, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.ID), query) || strings.Contains(strings.ToLower(item.Type), query) || strings.Contains(strings.ToLower(item.Host), query) || strings.Contains(strings.ToLower(item.Subnet), query) || strings.Contains(strings.ToLower(item.TLSServerName), query) {
			out = append(out, item)
		}
	}
	return out
}
func paginateV2[T any](items []T, page, pageSize int) []T {
	if pageSize <= 0 {
		return items
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []T{}
	}
	end := min(start+pageSize, len(items))
	return items[start:end]
}
