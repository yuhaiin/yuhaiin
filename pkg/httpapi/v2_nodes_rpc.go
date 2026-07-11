package httpapi

import (
	"context"
	"errors"
	"strings"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func addNodeRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2NodesGet, api.nodes)
	addRPCRoute(handlers, v2NodesPost, api.saveNode)
	addRPCRoute(handlers, v2NodesSelected, api.selectedNodes)
	addRPCRoute(handlers, v2NodesActive, api.activeNodes)
	addRPCRoute(handlers, v2NodeGet, api.node)
	addRPCRoute(handlers, v2NodePut, api.saveNode)
	addRPCRoute(handlers, v2NodeDelete, api.deleteNode)
	addRPCRoute(handlers, v2NodeUse, api.useNode)
	addRPCRoute(handlers, v2NodeLatency, api.nodeLatency)
	addRPCRoute(handlers, v2NodeClose, api.closeNode)
}

func addResolverRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2ResolversGet, api.resolvers)
	addRPCRoute(handlers, v2ResolversPost, api.saveResolver)
	addRPCRoute(handlers, v2ResolverGet, api.resolver)
	addRPCRoute(handlers, v2ResolverPut, api.saveResolver)
	addRPCRoute(handlers, v2ResolverDelete, api.deleteResolver)
}

func (a v2API) nodes(ctx context.Context, request *listRequest) (*listV2[contractnode.Node], error) {
	if a.services.Nodes == nil {
		return nil, unavailable("node store is unavailable")
	}
	items, err := a.services.Nodes.List(ctx)
	if err != nil {
		return nil, err
	}
	if query := strings.TrimSpace(request.Query); query != "" {
		items = filterNodes(items, query)
	}
	return pageResponse(items, request), nil
}
func (a v2API) saveNode(ctx context.Context, request *contractnode.Node) (*contractnode.Node, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	value, err := a.services.Node.Save(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	if a.services.Nodes != nil {
		if err := a.services.Nodes.Save(ctx, value, 0); err != nil {
			return nil, badRequest(err)
		}
	}
	return &value, nil
}
func (a v2API) selectedNodes(ctx context.Context, _ *emptyRequest) (*contractnode.Selection, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	return pointer(a.services.Node.Selected(ctx))
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
	removed := false
	if a.services.Node != nil {
		if err := a.services.Node.Remove(ctx, request.ID); err != nil {
			return nil, &rpcError{status: 404, code: "not_found", message: err.Error()}
		}
		removed = true
	}
	if a.services.Nodes != nil {
		if err := a.services.Nodes.Delete(ctx, request.ID); err != nil {
			if !removed || !errors.Is(err, plainstore.ErrNotFound) {
				return nil, err
			}
		}
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
	if err := a.services.Node.Close(ctx, request.ID); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
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
	if a.services.Resolvers != nil {
		if err := a.services.Resolvers.Save(ctx, value, 0); err != nil {
			return nil, badRequest(err)
		}
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
			return nil, &rpcError{status: 404, code: "not_found", message: err.Error()}
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
