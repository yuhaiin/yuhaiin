package control

import (
	"context"
	schemaapi "github.com/Asutorufa/yuhaiin/pkg/schema/api"
	schemabackup "github.com/Asutorufa/yuhaiin/pkg/schema/backup"
	schemaconfig "github.com/Asutorufa/yuhaiin/pkg/schema/config"
	schemanode "github.com/Asutorufa/yuhaiin/pkg/schema/node"
	schemastatistic "github.com/Asutorufa/yuhaiin/pkg/schema/statistic"
	schematools "github.com/Asutorufa/yuhaiin/pkg/schema/tools"
)

type ServerStream[T any] interface {
	Send(*T) error
	Context() context.Context
}

type ConfigPort interface {
	Load(context.Context, *schemaapi.Empty) (*schemaconfig.Setting, error)
	Save(context.Context, *schemaconfig.Setting) (*schemaapi.Empty, error)
	Info(context.Context, *schemaapi.Empty) (*schemaconfig.Info, error)
}

type ListsPort interface {
	List(context.Context, *schemaapi.Empty) (*schemaapi.ListResponse, error)
	ListPage(context.Context, *schemaapi.PageRequest) (*schemaapi.ListResponse, error)
	Get(context.Context, *schemaapi.StringValue) (*schemaconfig.List, error)
	Save(context.Context, *schemaconfig.List) (*schemaapi.Empty, error)
	Remove(context.Context, *schemaapi.StringValue) (*schemaapi.Empty, error)
	Refresh(context.Context, *schemaapi.Empty) (*schemaapi.Empty, error)
	SaveConfig(context.Context, *schemaapi.SaveListConfigRequest) (*schemaapi.Empty, error)
}

type RulesPort interface {
	List(context.Context, *schemaapi.Empty) (*schemaapi.RuleResponse, error)
	ListPage(context.Context, *schemaapi.PageRequest) (*schemaapi.RuleResponse, error)
	Get(context.Context, *schemaapi.RuleIndex) (*schemaconfig.Rulev2, error)
	Save(context.Context, *schemaapi.RuleSaveRequest) (*schemaapi.Empty, error)
	Remove(context.Context, *schemaapi.RuleIndex) (*schemaapi.Empty, error)
	ChangePriority(context.Context, *schemaapi.ChangePriorityRequest) (*schemaapi.Empty, error)
	Config(context.Context, *schemaapi.Empty) (*schemaconfig.Configv2, error)
	SaveConfig(context.Context, *schemaconfig.Configv2) (*schemaapi.Empty, error)
	Test(context.Context, *schemaapi.StringValue) (*schemaapi.TestResponse, error)
	BlockHistory(context.Context, *schemaapi.Empty) (*schemaapi.BlockHistoryList, error)
}

type InboundPort interface {
	List(context.Context, *schemaapi.Empty) (*schemaapi.InboundsResponse, error)
	ListPage(context.Context, *schemaapi.PageRequest) (*schemaapi.InboundsResponse, error)
	Get(context.Context, *schemaapi.StringValue) (*schemaconfig.Inbound, error)
	Save(context.Context, *schemaconfig.Inbound) (*schemaconfig.Inbound, error)
	Remove(context.Context, *schemaapi.StringValue) (*schemaapi.Empty, error)
	Apply(context.Context, *schemaapi.InboundsResponse) (*schemaapi.Empty, error)
	PlatformInfo(context.Context, *schemaapi.Empty) (*schemaapi.PlatformInfoResponse, error)
}

type ResolverPort interface {
	List(context.Context, *schemaapi.Empty) (*schemaapi.ResolveList, error)
	ListPage(context.Context, *schemaapi.PageRequest) (*schemaapi.ResolveList, error)
	Get(context.Context, *schemaapi.StringValue) (*schemaconfig.Dns, error)
	Save(context.Context, *schemaapi.SaveResolver) (*schemaconfig.Dns, error)
	Remove(context.Context, *schemaapi.StringValue) (*schemaapi.Empty, error)
	Hosts(context.Context, *schemaapi.Empty) (*schemaapi.Hosts, error)
	SaveHosts(context.Context, *schemaapi.Hosts) (*schemaapi.Empty, error)
	Fakedns(context.Context, *schemaapi.Empty) (*schemaconfig.FakednsConfig, error)
	SaveFakedns(context.Context, *schemaconfig.FakednsConfig) (*schemaapi.Empty, error)
	Server(context.Context, *schemaapi.Empty) (*schemaapi.StringValue, error)
	SaveServer(context.Context, *schemaapi.StringValue) (*schemaapi.Empty, error)
}

type NodePort interface {
	Now(context.Context, *schemaapi.Empty) (*schemaapi.NowResp, error)
	Use(context.Context, *schemaapi.UseReq) (*schemanode.Point, error)
	Get(context.Context, *schemaapi.StringValue) (*schemanode.Point, error)
	Save(context.Context, *schemanode.Point) (*schemanode.Point, error)
	Remove(context.Context, *schemaapi.StringValue) (*schemaapi.Empty, error)
	List(context.Context, *schemaapi.Empty) (*schemaapi.NodesResponse, error)
	Activates(context.Context, *schemaapi.Empty) (*schemaapi.ActivatesResponse, error)
	Close(context.Context, *schemaapi.StringValue) (*schemaapi.Empty, error)
	Latency(context.Context, *schemanode.Requests) (*schemanode.Response, error)
}

type SubscribePort interface {
	Save(context.Context, *schemaapi.SaveLinkReq) (*schemaapi.Empty, error)
	Remove(context.Context, *schemaapi.LinkReq) (*schemaapi.Empty, error)
	Update(context.Context, *schemaapi.LinkReq) (*schemaapi.Empty, error)
	Get(context.Context, *schemaapi.Empty) (*schemaapi.GetLinksResp, error)
	RemovePublish(context.Context, *schemaapi.StringValue) (*schemaapi.Empty, error)
	ListPublish(context.Context, *schemaapi.Empty) (*schemaapi.ListPublishResponse, error)
	SavePublish(context.Context, *schemaapi.SavePublishRequest) (*schemaapi.Empty, error)
	Publish(context.Context, *schemaapi.PublishRequest) (*schemaapi.PublishResponse, error)
}

type TagPort interface {
	Save(context.Context, *schemaapi.SaveTagReq) (*schemaapi.Empty, error)
	Remove(context.Context, *schemaapi.StringValue) (*schemaapi.Empty, error)
	List(context.Context, *schemaapi.Empty) (*schemaapi.TagsResponse, error)
	ListPage(context.Context, *schemaapi.TagPageRequest) (*schemaapi.TagsResponse, error)
}

type ConnectionsPort interface {
	Conns(context.Context, *schemaapi.Empty) (*schemaapi.NotifyNewConnections, error)
	CloseConn(context.Context, *schemaapi.NotifyRemoveConnections) (*schemaapi.Empty, error)
	Total(context.Context, *schemaapi.Empty) (*schemaapi.TotalFlow, error)
	Notify(*schemaapi.Empty, ServerStream[schemaapi.NotifyData]) error
	FailedHistory(context.Context, *schemaapi.Empty) (*schemaapi.FailedHistoryList, error)
	AllHistory(context.Context, *schemaapi.Empty) (*schemaapi.AllHistoryList, error)
}

type ToolsPort interface {
	GetInterface(context.Context, *schemaapi.Empty) (*schematools.Interfaces, error)
	Licenses(context.Context, *schemaapi.Empty) (*schematools.Licenses, error)
	Log(*schemaapi.Empty, ServerStream[schematools.Log]) error
	Logv2(*schemaapi.Empty, ServerStream[schematools.Logv2]) error
}

type BackupPort interface {
	Save(context.Context, *schemaconfig.BackupOption) (*schemaapi.Empty, error)
	Get(context.Context, *schemaapi.Empty) (*schemaconfig.BackupOption, error)
	Backup(context.Context, *schemaapi.Empty) (*schemaapi.Empty, error)
	Restore(context.Context, *schemabackup.RestoreOption) (*schemaapi.Empty, error)
}

type ConnectionInfoStore interface {
	Load(id uint64) (*schemastatistic.Connection, bool)
}
