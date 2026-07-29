package httpapi

import (
	"context"
	"errors"
	"strings"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type listRequest struct {
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	Query    string `json:"query"`
}

type idRequest struct {
	ID string `json:"id"`
}

func addInboundRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2InboundConfigGet, api.inboundConfig)
	addRPCRoute(handlers, v2InboundConfigPut, api.saveInboundConfig)
	addRPCRoute(handlers, v2InboundsGet, api.inbounds)
	addRPCRoute(handlers, v2InboundsPost, api.createInbound)
	addRPCRoute(handlers, v2InboundGet, api.inbound)
	addRPCRoute(handlers, v2InboundPut, api.saveInbound)
	addRPCRoute(handlers, v2InboundDelete, api.deleteInbound)
}

func (a v2API) inboundConfig(ctx context.Context, _ *emptyRequest) (*inboundConfigV2, error) {
	if a.services.Inbounds == nil {
		return nil, unavailable("inbound store is unavailable")
	}
	config, err := a.services.Inbounds.Settings(ctx)
	if err == nil {
		value := inboundConfigFromStoreV2(config)
		return &value, nil
	}
	value := defaultInboundConfigV2()
	if err := a.services.Inbounds.SaveSettings(ctx, inboundConfigToStoreV2(value)); err != nil {
		return &value, nil
	}
	return &value, nil
}

func (a v2API) saveInboundConfig(ctx context.Context, request *inboundConfigV2) (*inboundConfigV2, error) {
	if a.services.Inbounds == nil {
		return nil, unavailable("inbound store is unavailable")
	}
	if err := a.services.Inbounds.SaveSettings(ctx, inboundConfigToStoreV2(*request)); err != nil {
		return nil, badRequest(err)
	}
	return request, nil
}

func (a v2API) inbounds(ctx context.Context, request *listRequest) (*listV2[contractinbound.Inbound], error) {
	if a.services.Inbounds == nil {
		return nil, unavailable("inbound store is unavailable")
	}
	if store, ok := a.services.Inbounds.(interface {
		ListPage(context.Context, string, int, int) ([]contractinbound.Inbound, int, error)
	}); ok {
		items, total, err := store.ListPage(ctx, request.Query, request.Page, request.PageSize)
		if err != nil {
			return nil, err
		}
		return pageResponseWithTotal(items, total, request), nil
	}
	items, err := a.services.Inbounds.List(ctx)
	if err != nil {
		return nil, err
	}
	if query := strings.TrimSpace(request.Query); query != "" {
		items = filterInbounds(items, query)
	}
	return pageResponse(items, request), nil
}

func (a v2API) createInbound(ctx context.Context, request *contractinbound.Inbound) (*contractinbound.Inbound, error) {
	if a.services.Inbounds == nil {
		return nil, unavailable("inbound store is unavailable")
	}
	if strings.TrimSpace(request.ID) == "" {
		return nil, badRequest(errors.New("inbound id is empty"))
	}
	if err := a.services.Inbounds.Save(ctx, *request, 0); err != nil {
		return nil, badRequest(err)
	}
	return pointer(a.services.Inbounds.Get(ctx, request.ID))
}

func (a v2API) inbound(ctx context.Context, request *idRequest) (*contractinbound.Inbound, error) {
	if a.services.Inbounds == nil {
		return nil, unavailable("inbound store is unavailable")
	}
	value, err := a.services.Inbounds.Get(ctx, request.ID)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, &rpcError{status: 404, code: "not_found", message: err.Error()}
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (a v2API) saveInbound(ctx context.Context, request *contractinbound.Inbound) (*contractinbound.Inbound, error) {
	if a.services.Inbounds == nil {
		return nil, unavailable("inbound store is unavailable")
	}
	if err := a.services.Inbounds.Save(ctx, *request, 0); err != nil {
		return nil, badRequest(err)
	}
	return pointer(a.services.Inbounds.Get(ctx, request.ID))
}

func (a v2API) deleteInbound(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	if a.services.Inbounds == nil {
		return nil, unavailable("inbound store is unavailable")
	}
	if err := a.services.Inbounds.Delete(ctx, request.ID); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, &rpcError{status: 404, code: "not_found", message: err.Error()}
		}
		return nil, err
	}
	return &emptyResponse{}, nil
}

func pageResponse[T any](items []T, request *listRequest) *listV2[T] {
	return pageResponseWithTotal(paginateV2(items, max(request.Page, 1), max(request.PageSize, 0)), len(items), request)
}

func pageResponseWithTotal[T any](items []T, total int, request *listRequest) *listV2[T] {
	return &listV2[T]{Items: items, Page: pageInfo(request, total)}
}

func pageInfo(request *listRequest, total int) pageV2 {
	return pageV2{Page: max(request.Page, 1), PageSize: max(request.PageSize, 0), Total: total}
}
