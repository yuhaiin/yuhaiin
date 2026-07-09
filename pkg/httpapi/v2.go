package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
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

type ConnectionMonitor interface {
	Total(context.Context) (contractconnection.TotalFlow, error)
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
	Test(context.Context, string) (contractroute.RuleTestResponse, error)
	BlockHistory(context.Context) (contractroute.BlockHistoryList, error)
}

type ListRuntimeController interface {
	SaveConfig(context.Context, contractroute.ListConfig, uint64) error
	Refresh(context.Context) error
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
	registerSettingsV2(register, services)
	registerBackupV2(register, services)
	registerToolsV2(register, services)
	registerConnectionsV2(register, services)
	registerRouteV2(register, services)
	registerSubscriptionV2(register, services)

	registerNodeV2(register, services)
	registerResolverV2(register, services)
	registerResolverConfigV2(register, services)

	register("GET /api/v2/inbounds/config", func(w http.ResponseWriter, r *http.Request) error {
		if services.Inbounds == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "inbound store is unavailable")
		}
		config, err := services.Inbounds.Settings(r.Context())
		if err != nil {
			req := defaultInboundConfigV2()
			if saveErr := services.Inbounds.SaveSettings(r.Context(), inboundConfigToStoreV2(req)); saveErr != nil {
				return writeJSON(w, http.StatusOK, req)
			}
			return writeJSON(w, http.StatusOK, req)
		}
		return writeJSON(w, http.StatusOK, inboundConfigFromStoreV2(config))
	})

	register("PUT /api/v2/inbounds/config", func(w http.ResponseWriter, r *http.Request) error {
		if services.Inbounds == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "inbound store is unavailable")
		}
		var req inboundConfigV2
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.Inbounds.SaveSettings(r.Context(), inboundConfigToStoreV2(req)); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, req)
	})

	register("GET /api/v2/inbounds", func(w http.ResponseWriter, r *http.Request) error {
		if services.Inbounds == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "inbound store is unavailable")
		}
		items, err := services.Inbounds.List(r.Context())
		if err != nil {
			return err
		}

		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if query != "" {
			items = filterInbounds(items, query)
		}

		page, pageSize := pageV2FromQuery(r)
		total := len(items)
		items = paginateV2(items, page, pageSize)
		return writeJSON(w, http.StatusOK, listV2[contractinbound.Inbound]{
			Items: items,
			Page: pageV2{
				Page:     page,
				PageSize: pageSize,
				Total:    total,
			},
		})
	})

	register("POST /api/v2/inbounds", func(w http.ResponseWriter, r *http.Request) error {
		if services.Inbounds == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "inbound store is unavailable")
		}
		var inbound contractinbound.Inbound
		if err := readJSONBody(r, &inbound); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if strings.TrimSpace(inbound.ID) == "" {
			return writeError(w, http.StatusBadRequest, "bad_request", "inbound id is empty")
		}
		if err := services.Inbounds.Save(r.Context(), inbound, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		saved, err := services.Inbounds.Get(r.Context(), inbound.ID)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusCreated, saved)
	})

	register("GET /api/v2/inbounds/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if services.Inbounds == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "inbound store is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		inbound, err := services.Inbounds.Get(r.Context(), id)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, inbound)
	})

	register("PUT /api/v2/inbounds/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if services.Inbounds == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "inbound store is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var inbound contractinbound.Inbound
		if err := readJSONBody(r, &inbound); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		inbound.ID = id
		if err := services.Inbounds.Save(r.Context(), inbound, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		saved, err := services.Inbounds.Get(r.Context(), id)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, saved)
	})

	register("DELETE /api/v2/inbounds/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if services.Inbounds == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "inbound store is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		err = services.Inbounds.Delete(r.Context(), id)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
}

func defaultInboundConfigV2() inboundConfigV2 {
	return inboundConfigV2{
		HijackDNS:       true,
		HijackDNSFakeIP: true,
		Sniff:           true,
	}
}

func inboundConfigFromStoreV2(config plainstore.InboundSettings) inboundConfigV2 {
	return inboundConfigV2{
		HijackDNS:       config.HijackDNS,
		HijackDNSFakeIP: config.HijackDNSFakeIP,
		Sniff:           config.Sniff,
	}
}

func inboundConfigToStoreV2(config inboundConfigV2) plainstore.InboundSettings {
	return plainstore.InboundSettings{
		HijackDNS:       config.HijackDNS,
		HijackDNSFakeIP: config.HijackDNSFakeIP,
		Sniff:           config.Sniff,
	}
}

func registerNodeV2(register RegisterFunc, services V2Services) {
	register("GET /api/v2/nodes", func(w http.ResponseWriter, r *http.Request) error {
		if services.Nodes == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "node store is unavailable")
		}
		items, err := services.Nodes.List(r.Context())
		if err != nil {
			return err
		}
		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if query != "" {
			items = filterNodes(items, query)
		}
		page, pageSize := pageV2FromQuery(r)
		total := len(items)
		items = paginateV2(items, page, pageSize)
		return writeJSON(w, http.StatusOK, listV2[contractnode.Node]{
			Items: items,
			Page: pageV2{
				Page:     page,
				PageSize: pageSize,
				Total:    total,
			},
		})
	})

	register("POST /api/v2/nodes", func(w http.ResponseWriter, r *http.Request) error {
		return saveNodeV2(w, r, services, "", http.StatusCreated)
	})

	register("GET /api/v2/nodes/selected", func(w http.ResponseWriter, r *http.Request) error {
		if services.Node == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "node controller is unavailable")
		}
		resp, err := services.Node.Selected(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})

	register("GET /api/v2/nodes/active", func(w http.ResponseWriter, r *http.Request) error {
		if services.Node == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "node controller is unavailable")
		}
		items, err := services.Node.Active(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, struct {
			Items []contractnode.Node `json:"items"`
		}{Items: items})
	})

	register("GET /api/v2/nodes/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if services.Nodes == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "node store is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		node, err := services.Nodes.Get(r.Context(), id)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, node)
	})

	register("PUT /api/v2/nodes/{id}", func(w http.ResponseWriter, r *http.Request) error {
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return saveNodeV2(w, r, services, id, http.StatusOK)
	})

	register("DELETE /api/v2/nodes/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if services.Node == nil && services.Nodes == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "node service is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		removedRuntime := false
		if services.Node != nil {
			if err := services.Node.Remove(r.Context(), id); err != nil {
				return writeError(w, http.StatusNotFound, "not_found", err.Error())
			}
			removedRuntime = true
		}
		if services.Nodes != nil {
			err := services.Nodes.Delete(r.Context(), id)
			if errors.Is(err, plainstore.ErrNotFound) && !removedRuntime {
				return writeError(w, http.StatusNotFound, "not_found", err.Error())
			}
			if err != nil && !errors.Is(err, plainstore.ErrNotFound) {
				return err
			}
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("POST /api/v2/nodes/{id}/use", func(w http.ResponseWriter, r *http.Request) error {
		if services.Node == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "node controller is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.Node.Use(r.Context(), id); err != nil {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("POST /api/v2/nodes/{id}/latency", func(w http.ResponseWriter, r *http.Request) error {
		if services.Node == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "node controller is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var req contractnode.LatencyRequest
		if r.Body != nil && r.ContentLength != 0 {
			if err := readJSONBody(r, &req); err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
		}
		reply, err := services.Node.Latency(r.Context(), id, req)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, reply)
	})

	register("POST /api/v2/nodes/{id}/close", func(w http.ResponseWriter, r *http.Request) error {
		if services.Node == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "node controller is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.Node.Close(r.Context(), id); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
}

func registerResolverV2(register RegisterFunc, services V2Services) {
	register("GET /api/v2/resolvers", func(w http.ResponseWriter, r *http.Request) error {
		if services.Resolvers == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver store is unavailable")
		}
		items, err := services.Resolvers.List(r.Context())
		if err != nil {
			return err
		}
		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if query != "" {
			items = filterResolvers(items, query)
		}
		page, pageSize := pageV2FromQuery(r)
		total := len(items)
		items = paginateV2(items, page, pageSize)
		return writeJSON(w, http.StatusOK, listV2[contractresolver.Resolver]{
			Items: items,
			Page:  pageV2{Page: page, PageSize: pageSize, Total: total},
		})
	})

	register("POST /api/v2/resolvers", func(w http.ResponseWriter, r *http.Request) error {
		return saveResolverV2(w, r, services, "", http.StatusCreated)
	})

	register("GET /api/v2/resolvers/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if services.Resolvers == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver store is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resolver, err := services.Resolvers.Get(r.Context(), id)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resolver)
	})

	register("PUT /api/v2/resolvers/{id}", func(w http.ResponseWriter, r *http.Request) error {
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return saveResolverV2(w, r, services, id, http.StatusOK)
	})

	register("DELETE /api/v2/resolvers/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if services.Resolver == nil && services.Resolvers == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver service is unavailable")
		}
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		removedRuntime := false
		if services.Resolver != nil {
			if err := services.Resolver.Remove(r.Context(), id); err != nil {
				return writeError(w, http.StatusNotFound, "not_found", err.Error())
			}
			removedRuntime = true
		}
		if services.Resolvers != nil {
			err := services.Resolvers.Delete(r.Context(), id)
			if errors.Is(err, plainstore.ErrNotFound) && !removedRuntime {
				return writeError(w, http.StatusNotFound, "not_found", err.Error())
			}
			if err != nil && !errors.Is(err, plainstore.ErrNotFound) {
				return err
			}
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
}

func filterResolvers(items []contractresolver.Resolver, query string) []contractresolver.Resolver {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return items
	}
	out := make([]contractresolver.Resolver, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.ID), query) ||
			strings.Contains(strings.ToLower(item.Type), query) ||
			strings.Contains(strings.ToLower(item.Host), query) ||
			strings.Contains(strings.ToLower(item.Subnet), query) ||
			strings.Contains(strings.ToLower(item.TLSServerName), query) {
			out = append(out, item)
		}
	}
	return out
}

func saveResolverV2(w http.ResponseWriter, r *http.Request, services V2Services, id string, status int) error {
	if services.Resolver == nil {
		return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver controller is unavailable")
	}
	var resolver contractresolver.Resolver
	if err := readJSONBody(r, &resolver); err != nil {
		return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	}
	if id != "" {
		resolver.ID = id
	}
	converted, err := services.Resolver.Save(r.Context(), resolver)
	if err != nil {
		return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	}
	if services.Resolvers != nil {
		if err := services.Resolvers.Save(r.Context(), converted, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
	}
	return writeJSON(w, status, converted)
}

func saveNodeV2(w http.ResponseWriter, r *http.Request, services V2Services, id string, status int) error {
	if services.Node == nil {
		return writeError(w, http.StatusServiceUnavailable, "unavailable", "node controller is unavailable")
	}
	var node contractnode.Node
	if err := readJSONBody(r, &node); err != nil {
		return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	}
	if id != "" {
		node.ID = id
	}
	converted, err := services.Node.Save(r.Context(), node)
	if err != nil {
		return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	}
	if services.Nodes != nil {
		if err := services.Nodes.Save(r.Context(), converted, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
	}
	return writeJSON(w, status, converted)
}

func filterInbounds(items []contractinbound.Inbound, query string) []contractinbound.Inbound {
	query = strings.ToLower(query)
	filtered := make([]contractinbound.Inbound, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.ID), query) ||
			strings.Contains(strings.ToLower(item.Name), query) ||
			strings.Contains(strings.ToLower(item.Network.Type), query) ||
			strings.Contains(strings.ToLower(item.Protocol.Type), query) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func filterNodes(items []contractnode.Node, query string) []contractnode.Node {
	query = strings.ToLower(query)
	filtered := make([]contractnode.Node, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.ID), query) ||
			strings.Contains(strings.ToLower(item.Name), query) ||
			strings.Contains(strings.ToLower(item.Group), query) ||
			strings.Contains(strings.ToLower(item.Origin), query) ||
			nodeChainContains(item, query) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func nodeChainContains(item contractnode.Node, query string) bool {
	for _, protocol := range item.Chain {
		if strings.Contains(strings.ToLower(protocol.Type), query) {
			return true
		}
	}
	return false
}

func pageV2FromQuery(r *http.Request) (int, int) {
	page := positiveQueryInt(r, "page", 1)
	pageSize := positiveQueryInt(r, "page_size", 0)
	if pageSize == 0 {
		pageSize = positiveQueryInt(r, "pageSize", 0)
	}
	return page, pageSize
}

func positiveQueryInt(r *http.Request, key string, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return fallback
	}
	return value
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
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}
