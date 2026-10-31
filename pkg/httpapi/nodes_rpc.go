package httpapi

import (
	"context"
	"errors"
	"strings"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	runtimenode "github.com/Asutorufa/yuhaiin/pkg/node"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func addNodeRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2NodesGet, api.nodes)
	addRPCRoute(handlers, v2NodesGroups, api.nodeGroups)
	addRPCRoute(handlers, v2NodesPost, api.saveNode)
	addRPCRoute(handlers, v2NodesImportPreview, api.previewNodeImport)
	addRPCRoute(handlers, v2NodesSelected, api.selectedNodes)
	addRPCRoute(handlers, v2NodesSelect, api.selectNodes)
	addRPCRoute(handlers, v2NodesActive, api.activeNodes)
	addRPCRoute(handlers, v2NodeStatuses, api.nodeStatuses)
	addRPCRoute(handlers, v2NodeGet, api.node)
	addRPCRoute(handlers, v2NodePut, api.saveNode)
	addRPCRoute(handlers, v2NodeDelete, api.deleteNode)
	addRPCRoute(handlers, v2NodeUse, api.useNode)
	addRPCRoute(handlers, v2NodeLatency, api.nodeLatency)
	addRPCRoute(handlers, v2NodeSpeed, api.nodeSpeed)
	addRPCRoute(handlers, v2NodeClose, api.closeNode)
	addRPCRoute(handlers, v2NodeExtraInfo, api.nodeExtraInfo)
}

type nodeStatusRequest struct {
	IDs []string `json:"ids"`
}

func (a v2API) nodeStatuses(ctx context.Context, request *nodeStatusRequest) (*struct {
	Items []contractnode.RuntimeStatus `json:"items"`
}, error) {
	provider, ok := a.services.Node.(interface {
		Statuses(context.Context, []string) ([]contractnode.RuntimeStatus, error)
	})
	if !ok {
		return nil, unavailable("outbound observability is unavailable")
	}
	if len(request.IDs) > 100 {
		return nil, badRequest(errors.New("at most 100 node IDs are permitted"))
	}
	items, err := provider.Statuses(ctx, request.IDs)
	if err != nil {
		return nil, err
	}
	return &struct {
		Items []contractnode.RuntimeStatus `json:"items"`
	}{Items: items}, nil
}

func (a v2API) previewNodeImport(_ context.Context, request *contractnode.ImportRequest) (*contractnode.ImportPreview, error) {
	preview, err := runtimenode.PreviewImport(*request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &preview, nil
}

func addResolverRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2ResolversGet, api.resolvers)
	addRPCRoute(handlers, v2ResolversPost, api.saveResolver)
	addRPCRoute(handlers, v2ResolverGet, api.resolver)
	addRPCRoute(handlers, v2ResolverPut, api.saveResolver)
	addRPCRoute(handlers, v2HostEntries, api.hostEntries)
	addRPCRoute(handlers, v2HostEntryGet, api.hostEntry)
	addRPCRoute(handlers, v2HostEntryPost, api.createHostEntry)
	addRPCRoute(handlers, v2HostEntryPut, api.saveHostEntry)
	addRPCRoute(handlers, v2HostEntryDelete, api.deleteHostEntry)
	addRPCRoute(handlers, v2ResolverTest, api.testResolver)
	addRPCRoute(handlers, v2ResolverQueryTypes, api.resolverQueryTypes)
	addRPCRoute(handlers, v2ResolverDelete, api.deleteResolver)
	addRPCRoute(handlers, v2ResolverCacheGet, api.resolverCache)
	addRPCRoute(handlers, v2ResolverCacheDelete, api.clearResolverCache)
}

type nodeListRequest struct {
	listRequest
	Group       string `json:"group"`
	EnabledOnly bool   `json:"enabled_only"`
}

type nodeGroupsResponse struct {
	Items []plainstore.NodeGroupSummary `json:"items"`
}

// A group selection must never fetch and decode the entire node database.
func (a v2API) nodeGroups(ctx context.Context, _ *emptyRequest) (*nodeGroupsResponse, error) {
	if a.services.Nodes == nil {
		return nil, unavailable("node store is unavailable")
	}
	groups, err := a.services.Nodes.Groups(ctx)
	if err != nil {
		return nil, err
	}
	return &nodeGroupsResponse{Items: groups}, nil
}

func (a v2API) nodes(ctx context.Context, request *nodeListRequest) (*listV2[contractnode.Node], error) {
	if a.services.Nodes == nil {
		return nil, unavailable("node store is unavailable")
	}
	page, size := max(request.Page, 1), request.PageSize
	if size <= 0 {
		size = 100
	}
	size = min(size, 100)
	items, total, err := a.services.Nodes.ListPage(ctx, request.Group, request.Query, request.EnabledOnly, page, size)
	if err != nil {
		return nil, err
	}
	return &listV2[contractnode.Node]{Items: items, Page: pageV2{Page: page, PageSize: size, Total: total}}, nil
}

func (a v2API) saveNode(ctx context.Context, request *contractnode.Node) (*contractnode.Node, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	value, err := a.services.Node.Save(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}
func (a v2API) selectedNodes(ctx context.Context, _ *emptyRequest) (*contractnode.Selection, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	return pointer(a.services.Node.Selected(ctx))
}

func (a v2API) selectNodes(ctx context.Context, request *contractnode.SelectionRequest) (*emptyResponse, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	if err := a.services.Node.Select(ctx, *request); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}
func (a v2API) activeNodes(ctx context.Context, _ *emptyRequest) (*struct {
	Items []contractnode.Node `json:"items"`
}, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	items, err := a.services.Node.Active(ctx)
	return &struct {
		Items []contractnode.Node `json:"items"`
	}{Items: items}, err
}
func (a v2API) node(ctx context.Context, request *idRequest) (*contractnode.Node, error) {
	if a.services.Nodes == nil {
		return nil, unavailable("node store is unavailable")
	}
	value, err := a.services.Nodes.Get(ctx, request.ID)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, &rpcError{status: 404, code: "not_found", message: err.Error()}
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}
func (a v2API) deleteNode(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	if a.services.Node == nil && a.services.Nodes == nil {
		return nil, unavailable("node service is unavailable")
	}
	if a.services.Node != nil {
		if err := a.services.Node.Remove(ctx, request.ID); err != nil {
			if errors.Is(err, plainstore.ErrNotFound) {
				return nil, notFound(err)
			}
			return nil, err
		}
		return &emptyResponse{}, nil
	}
	if err := a.services.Nodes.Delete(ctx, request.ID); err != nil {
		return nil, err
	}
	return &emptyResponse{}, nil
}
func (a v2API) useNode(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	if err := a.services.Node.Use(ctx, request.ID); err != nil {
		return nil, &rpcError{status: 404, code: "not_found", message: err.Error()}
	}
	return &emptyResponse{}, nil
}

type latencyRequest struct {
	ID string `json:"id"`
	contractnode.LatencyRequest
}

func (a v2API) nodeLatency(ctx context.Context, request *latencyRequest) (*contractnode.LatencyResponse, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	value, err := a.services.Node.Latency(ctx, request.ID, request.LatencyRequest)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}
func (a v2API) closeNode(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	if err := a.services.Node.CloseNode(ctx, request.ID); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}

func (a v2API) nodeExtraInfo(ctx context.Context, request *idRequest) (*contractnode.NodeExtraInfo, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	info, err := a.services.Node.ExtraInfo(ctx, request.ID)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(errors.New("node is not active or has no runtime extra information"))
	}
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func (a v2API) resolvers(ctx context.Context, request *listRequest) (*listV2[contractresolver.Resolver], error) {
	if a.services.Resolvers == nil {
		return nil, unavailable("resolver store is unavailable")
	}
	items, err := a.services.Resolvers.List(ctx)
	if err != nil {
		return nil, err
	}
	if query := strings.TrimSpace(request.Query); query != "" {
		items = filterResolvers(items, query)
	}
	return pageResponse(items, request), nil
}
func (a v2API) saveResolver(ctx context.Context, request *contractresolver.Resolver) (*contractresolver.Resolver, error) {
	if a.services.Resolver == nil {
		return nil, unavailable("resolver controller is unavailable")
	}
	value, err := a.services.Resolver.Save(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}
func (a v2API) resolver(ctx context.Context, request *idRequest) (*contractresolver.Resolver, error) {
	if a.services.Resolvers == nil {
		return nil, unavailable("resolver store is unavailable")
	}
	value, err := a.services.Resolvers.Get(ctx, request.ID)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, &rpcError{status: 404, code: "not_found", message: err.Error()}
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}
func (a v2API) deleteResolver(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	if a.services.Resolver == nil && a.services.Resolvers == nil {
		return nil, unavailable("resolver service is unavailable")
	}
	removed := false
	if a.services.Resolver != nil {
		if err := a.services.Resolver.Remove(ctx, request.ID); err != nil {
			if errors.Is(err, plainstore.ErrNotFound) {
				return nil, notFound(err)
			}
			return nil, err
		}
		removed = true
	}
	if a.services.Resolvers != nil {
		if err := a.services.Resolvers.Delete(ctx, request.ID); err != nil {
			if !removed || !errors.Is(err, plainstore.ErrNotFound) {
				return nil, err
			}
		}
	}
	return &emptyResponse{}, nil
}

func (a v2API) resolverCache(ctx context.Context, _ *emptyRequest) (*contractresolver.DNSCacheList, error) {
	if a.services.ResolverCache == nil {
		return nil, unavailable("resolver cache controller is unavailable")
	}
	return pointer(a.services.ResolverCache.Cache(ctx))
}

type resolverCacheDeleteRequest struct {
	Resolver string `json:"resolver"`
	Domain   string `json:"domain"`
}

func (a v2API) clearResolverCache(ctx context.Context, request *resolverCacheDeleteRequest) (*contractresolver.DNSCacheClearResponse, error) {
	if a.services.ResolverCache == nil {
		return nil, unavailable("resolver cache controller is unavailable")
	}
	if strings.TrimSpace(request.Resolver) == "" {
		return nil, badRequest(errors.New("resolver is empty"))
	}
	if strings.TrimSpace(request.Domain) == "" {
		return nil, badRequest(errors.New("domain is empty"))
	}
	value, err := a.services.ResolverCache.ClearCache(ctx, request.Resolver, request.Domain)
	if errors.Is(err, contractresolver.ErrDNSCacheNotFound) {
		return nil, notFound(err)
	}
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}

type nodeSpeedRequest struct {
	ID string `json:"id"`
	contractnode.SpeedTestRequest
}

func (a v2API) nodeSpeed(ctx context.Context, request *nodeSpeedRequest) (*contractnode.ThroughputMeasurement, error) {
	provider, ok := a.services.Node.(interface {
		Speed(context.Context, string, contractnode.SpeedTestRequest) (contractnode.ThroughputMeasurement, error)
	})
	if !ok {
		return nil, unavailable("node speed measurement is unavailable")
	}
	result, err := provider.Speed(ctx, request.ID, request.SpeedTestRequest)
	if err != nil {
		return nil, badRequest(err)
	}
	return &result, nil
}
