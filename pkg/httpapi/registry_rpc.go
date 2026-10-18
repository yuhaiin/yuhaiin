package httpapi

import (
	"context"
	"errors"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func addRegistryRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2RouteRegistriesGet, api.routeRegistries)
	addRPCRoute(handlers, v2RouteRegistriesPost, api.createRouteRegistry)
	addRPCRoute(handlers, v2RouteRegistryPut, api.saveRouteRegistry)
	addRPCRoute(handlers, v2RouteRegistryDelete, api.deleteRouteRegistry)
	addRPCRoute(handlers, v2RouteRegistryCatalogs, api.routeRegistryCatalogs)
}

func (a v2API) routeRegistries(ctx context.Context, _ *emptyRequest) (*contractroute.RegistryList, error) {
	if a.services.RouteRegistries == nil {
		return nil, unavailable("route registry store is unavailable")
	}
	return pointer(a.services.RouteRegistries.ListRegistries(ctx))
}

func (a v2API) createRouteRegistry(ctx context.Context, request *contractroute.Registry) (*contractroute.Registry, error) {
	if a.services.RouteRegistries == nil {
		return nil, unavailable("route registry store is unavailable")
	}
	value, err := a.services.RouteRegistries.SaveRegistry(ctx, *request, 0)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}

type routeRegistrySaveRequest struct {
	ID string `json:"id"`
	contractroute.Registry
}

func (a v2API) saveRouteRegistry(ctx context.Context, request *routeRegistrySaveRequest) (*contractroute.Registry, error) {
	if a.services.RouteRegistries == nil {
		return nil, unavailable("route registry store is unavailable")
	}
	request.Registry.ID = request.ID
	value, err := a.services.RouteRegistries.SaveRegistry(ctx, request.Registry, 0)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}

func (a v2API) deleteRouteRegistry(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	if a.services.RouteRegistries == nil {
		return nil, unavailable("route registry store is unavailable")
	}
	if err := a.services.RouteRegistries.DeleteRegistry(ctx, request.ID); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, notFound(err)
		}
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}

type routeRegistryCatalogRequest struct {
	Refresh bool `json:"refresh"`
}

func (a v2API) routeRegistryCatalogs(ctx context.Context, request *routeRegistryCatalogRequest) (*contractroute.RegistryCatalogList, error) {
	if a.services.RegistryCatalogs == nil {
		return nil, unavailable("route registry catalog service is unavailable")
	}
	return pointer(a.services.RegistryCatalogs.Catalogs(ctx, request.Refresh))
}
