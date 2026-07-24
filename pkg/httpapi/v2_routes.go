package httpapi

import (
	"fmt"
	"net/http"
)

// v2Endpoint is a stable handler identifier. HTTP methods and URL patterns are
// intentionally kept in v2Routes, away from the handler implementation.
type v2Endpoint string

type v2Route struct {
	endpoint v2Endpoint
	pattern  string
}

func v2RoutePattern(route v2Route) string {
	if isV2StreamEndpoint(route.endpoint) {
		return route.pattern
	}
	return "POST /api/v2/rpc/" + string(route.endpoint)
}

func isV2StreamEndpoint(endpoint v2Endpoint) bool {
	return endpoint == v2ToolsLogs || endpoint == v2ToolsLogsV2 || endpoint == v2ConnectionsEvents
}

const (
	v2Info                     v2Endpoint = "info"
	v2UpdateCheck              v2Endpoint = "update.check"
	v2UpdateApply              v2Endpoint = "update.apply"
	v2UpdateStatus             v2Endpoint = "update.status"
	v2BackupRun                v2Endpoint = "backup.run"
	v2BackupRestore            v2Endpoint = "backup.restore"
	v2ToolsInterfaces          v2Endpoint = "tools.interfaces"
	v2ToolsLicenses            v2Endpoint = "tools.licenses"
	v2ToolsLogs                v2Endpoint = "tools.logs"
	v2ToolsLogsV2              v2Endpoint = "tools.logs.v2"
	v2ConnectionsTotal         v2Endpoint = "connections.total"
	v2ConnectionsTraffic       v2Endpoint = "connections.traffic"
	v2ConnectionsTelemetry     v2Endpoint = "connections.telemetry"
	v2ConnectionsEvents        v2Endpoint = "connections.events"
	v2Connections              v2Endpoint = "connections"
	v2ConnectionsClose         v2Endpoint = "connections.close"
	v2ConnectionsFailedHistory v2Endpoint = "connections.failed_history"
	v2ConnectionsHistory       v2Endpoint = "connections.history"
	v2SubscriptionsUpdate      v2Endpoint = "subscriptions.update"
	v2Publishes                v2Endpoint = "publishes"
	v2PublishResolve           v2Endpoint = "publish.resolve"
	v2NodesSelected            v2Endpoint = "nodes.selected"
	v2NodesActive              v2Endpoint = "nodes.active"
	v2NodeUse                  v2Endpoint = "node.use"
	v2NodeLatency              v2Endpoint = "node.latency"
	v2NodeClose                v2Endpoint = "node.close"
	v2RouteActivation          v2Endpoint = "route.activation"
	v2RouteApply               v2Endpoint = "route.apply"
	v2RouteListRefresh         v2Endpoint = "route.lists.refresh"
	v2RouteListActivation      v2Endpoint = "route.lists.activation"
	v2RouteRulesPriority       v2Endpoint = "route.rules.priority"
	v2RouteRulesTest           v2Endpoint = "route.rules.test"
	v2RouteRulesBlockHistory   v2Endpoint = "route.rules.block_history"

	v2SettingsGet         v2Endpoint = "settings.get"
	v2SettingsPut         v2Endpoint = "settings.put"
	v2BackupConfigGet     v2Endpoint = "backup.config.get"
	v2BackupConfigPut     v2Endpoint = "backup.config.put"
	v2ResolverHostsGet    v2Endpoint = "resolver.hosts.get"
	v2ResolverHostsPut    v2Endpoint = "resolver.hosts.put"
	v2ResolverFakeDNSGet  v2Endpoint = "resolver.fakedns.get"
	v2ResolverFakeDNSPut  v2Endpoint = "resolver.fakedns.put"
	v2ResolverServerGet   v2Endpoint = "resolver.server.get"
	v2ResolverServerPut   v2Endpoint = "resolver.server.put"
	v2SubscriptionsGet    v2Endpoint = "subscriptions.get"
	v2SubscriptionsPut    v2Endpoint = "subscriptions.put"
	v2SubscriptionsDelete v2Endpoint = "subscriptions.delete"
	v2PublishPut          v2Endpoint = "publish.put"
	v2PublishDelete       v2Endpoint = "publish.delete"
	v2InboundConfigGet    v2Endpoint = "inbounds.config.get"
	v2InboundConfigPut    v2Endpoint = "inbounds.config.put"
	v2InboundsGet         v2Endpoint = "inbounds.get"
	v2InboundsPost        v2Endpoint = "inbounds.post"
	v2InboundGet          v2Endpoint = "inbound.get"
	v2InboundPut          v2Endpoint = "inbound.put"
	v2InboundDelete       v2Endpoint = "inbound.delete"
	v2UsersGet            v2Endpoint = "users.get"
	v2UsersPost           v2Endpoint = "users.post"
	v2UserGet             v2Endpoint = "user.get"
	v2UserPut             v2Endpoint = "user.put"
	v2UserDelete          v2Endpoint = "user.delete"
	v2NodesGet            v2Endpoint = "nodes.get"
	v2NodesPost           v2Endpoint = "nodes.post"
	v2NodeGet             v2Endpoint = "node.get"
	v2NodePut             v2Endpoint = "node.put"
	v2NodeDelete          v2Endpoint = "node.delete"
	v2ResolversGet        v2Endpoint = "resolvers.get"
	v2ResolversPost       v2Endpoint = "resolvers.post"
	v2ResolverGet         v2Endpoint = "resolver.get"
	v2ResolverPut         v2Endpoint = "resolver.put"
	v2ResolverDelete      v2Endpoint = "resolver.delete"
	v2RouteConfigGet      v2Endpoint = "route.config.get"
	v2RouteConfigPut      v2Endpoint = "route.config.put"
	v2RouteListsGet       v2Endpoint = "route.lists.get"
	v2RouteListsPost      v2Endpoint = "route.lists.post"
	v2RouteListConfigGet  v2Endpoint = "route.lists.config.get"
	v2RouteListConfigPut  v2Endpoint = "route.lists.config.put"
	v2RouteListGet        v2Endpoint = "route.list.get"
	v2RouteListPut        v2Endpoint = "route.list.put"
	v2RouteListDelete     v2Endpoint = "route.list.delete"
	v2RouteRulesGet       v2Endpoint = "route.rules.get"
	v2RouteRulesPost      v2Endpoint = "route.rules.post"
	v2RouteRuleGet        v2Endpoint = "route.rule.get"
	v2RouteRulePut        v2Endpoint = "route.rule.put"
	v2RouteRuleDelete     v2Endpoint = "route.rule.delete"
	v2RouteTagsGet        v2Endpoint = "route.tags.get"
	v2RouteTagPut         v2Endpoint = "route.tag.put"
	v2RouteTagDelete      v2Endpoint = "route.tag.delete"
)

var v2Routes = []v2Route{
	{v2Info, "GET /api/v2/info"},
	{v2UpdateCheck, "POST /api/v2/update/check"},
	{v2UpdateApply, "POST /api/v2/update/apply"},
	{v2UpdateStatus, "GET /api/v2/update/status"},
	{v2SettingsGet, "GET /api/v2/settings"},
	{v2SettingsPut, "PUT /api/v2/settings"},
	{v2BackupConfigGet, "GET /api/v2/backup/config"},
	{v2BackupConfigPut, "PUT /api/v2/backup/config"},
	{v2BackupRun, "POST /api/v2/backup/run"},
	{v2BackupRestore, "POST /api/v2/backup/restore"},
	{v2ToolsInterfaces, "GET /api/v2/tools/interfaces"},
	{v2ToolsLicenses, "GET /api/v2/tools/licenses"},
	{v2ToolsLogs, "GET /api/v2/tools/logs"},
	{v2ToolsLogsV2, "GET /api/v2/tools/logs/v2"},
	{v2ConnectionsTotal, "GET /api/v2/connections/total"},
	{v2ConnectionsTraffic, "GET /api/v2/connections/traffic"},
	{v2ConnectionsTelemetry, "GET /api/v2/connections/telemetry"},
	{v2ConnectionsEvents, "GET /api/v2/connections/events"},
	{v2Connections, "GET /api/v2/connections"},
	{v2ConnectionsClose, "POST /api/v2/connections/close"},
	{v2ConnectionsFailedHistory, "GET /api/v2/connections/failed-history"},
	{v2ConnectionsHistory, "GET /api/v2/connections/history"},
	{v2ResolverHostsGet, "GET /api/v2/resolver/hosts"},
	{v2ResolverHostsPut, "PUT /api/v2/resolver/hosts"},
	{v2ResolverFakeDNSGet, "GET /api/v2/resolver/fakedns"},
	{v2ResolverFakeDNSPut, "PUT /api/v2/resolver/fakedns"},
	{v2ResolverServerGet, "GET /api/v2/resolver/server"},
	{v2ResolverServerPut, "PUT /api/v2/resolver/server"},
	{v2SubscriptionsGet, "GET /api/v2/subscriptions"},
	{v2SubscriptionsPut, "PUT /api/v2/subscriptions"},
	{v2SubscriptionsDelete, "DELETE /api/v2/subscriptions"},
	{v2SubscriptionsUpdate, "POST /api/v2/subscriptions/update"},
	{v2Publishes, "GET /api/v2/publishes"},
	{v2PublishPut, "PUT /api/v2/publishes/{name}"},
	{v2PublishDelete, "DELETE /api/v2/publishes/{name}"},
	{v2PublishResolve, "POST /api/v2/publishes/{name}/resolve"},
	{v2InboundConfigGet, "GET /api/v2/inbounds/config"},
	{v2InboundConfigPut, "PUT /api/v2/inbounds/config"},
	{v2InboundsGet, "GET /api/v2/inbounds"},
	{v2InboundsPost, "POST /api/v2/inbounds"},
	{v2InboundGet, "GET /api/v2/inbounds/{id}"},
	{v2InboundPut, "PUT /api/v2/inbounds/{id}"},
	{v2InboundDelete, "DELETE /api/v2/inbounds/{id}"},
	{v2UsersGet, "GET /api/v2/users"},
	{v2UsersPost, "POST /api/v2/users"},
	{v2UserGet, "GET /api/v2/users/{id}"},
	{v2UserPut, "PUT /api/v2/users/{id}"},
	{v2UserDelete, "DELETE /api/v2/users/{id}"},
	{v2NodesGet, "GET /api/v2/nodes"},
	{v2NodesPost, "POST /api/v2/nodes"},
	{v2NodesSelected, "GET /api/v2/nodes/selected"},
	{v2NodesActive, "GET /api/v2/nodes/active"},
	{v2NodeGet, "GET /api/v2/nodes/{id}"},
	{v2NodePut, "PUT /api/v2/nodes/{id}"},
	{v2NodeDelete, "DELETE /api/v2/nodes/{id}"},
	{v2NodeUse, "POST /api/v2/nodes/{id}/use"},
	{v2NodeLatency, "POST /api/v2/nodes/{id}/latency"},
	{v2NodeClose, "POST /api/v2/nodes/{id}/close"},
	{v2ResolversGet, "GET /api/v2/resolvers"},
	{v2ResolversPost, "POST /api/v2/resolvers"},
	{v2ResolverGet, "GET /api/v2/resolvers/{id}"},
	{v2ResolverPut, "PUT /api/v2/resolvers/{id}"},
	{v2ResolverDelete, "DELETE /api/v2/resolvers/{id}"},
	{v2RouteActivation, "GET /api/v2/route/activation"},
	{v2RouteApply, "POST /api/v2/route/apply"},
	{v2RouteConfigGet, "GET /api/v2/route/config"},
	{v2RouteConfigPut, "PUT /api/v2/route/config"},
	{v2RouteListsGet, "GET /api/v2/route/lists"},
	{v2RouteListConfigGet, "GET /api/v2/route/lists/config"},
	{v2RouteListConfigPut, "PUT /api/v2/route/lists/config"},
	{v2RouteListRefresh, "POST /api/v2/route/lists/refresh"},
	{v2RouteListActivation, "GET /api/v2/route/lists/activation"},
	{v2RouteListsPost, "POST /api/v2/route/lists"},
	{v2RouteListGet, "GET /api/v2/route/lists/{id}"},
	{v2RouteListPut, "PUT /api/v2/route/lists/{id}"},
	{v2RouteListDelete, "DELETE /api/v2/route/lists/{id}"},
	{v2RouteRulesGet, "GET /api/v2/route/rules"},
	{v2RouteRulesPost, "POST /api/v2/route/rules"},
	{v2RouteRulesPriority, "POST /api/v2/route/rules/priority"},
	{v2RouteRuleGet, "GET /api/v2/route/rules/{name}/{index}"},
	{v2RouteRulePut, "PUT /api/v2/route/rules/{name}/{index}"},
	{v2RouteRuleDelete, "DELETE /api/v2/route/rules/{name}/{index}"},
	{v2RouteRulesTest, "POST /api/v2/route/rules/test"},
	{v2RouteRulesBlockHistory, "GET /api/v2/route/rules/block-history"},
	{v2RouteTagsGet, "GET /api/v2/route/tags"},
	{v2RouteTagPut, "PUT /api/v2/route/tags/{tag}"},
	{v2RouteTagDelete, "DELETE /api/v2/route/tags/{tag}"},
}

type v2Handlers struct {
	values map[v2Endpoint]func(http.ResponseWriter, *http.Request) error
}

func newV2Handlers(services V2Services) *v2Handlers {
	handlers := &v2Handlers{values: make(map[v2Endpoint]func(http.ResponseWriter, *http.Request) error)}
	addFacadeRPCRoutesV2(handlers, services)
	addRouteRPCRoutesV2(handlers, services)
	addSubscriptionRPCRoutesV2(handlers, services)
	addNodeRPCRoutesV2(handlers, services)
	addResolverRPCRoutesV2(handlers, services)
	addInboundRPCRoutesV2(handlers, services)
	addUserRPCRoutesV2(handlers, services)
	return handlers
}

func (h *v2Handlers) add(endpoint v2Endpoint, handler func(http.ResponseWriter, *http.Request) error) {
	if _, exists := h.values[endpoint]; exists {
		panic(fmt.Sprintf("duplicate v2 handler %q", endpoint))
	}
	h.values[endpoint] = handler
}

func (h *v2Handlers) handler(endpoint v2Endpoint) func(http.ResponseWriter, *http.Request) error {
	handler, ok := h.values[endpoint]
	if !ok {
		panic(fmt.Sprintf("missing v2 handler %q", endpoint))
	}
	return handler
}
