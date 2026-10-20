package httpapi

import (
	"context"
	"errors"
	"strings"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
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
	addRPCRoute(handlers, v2TrafficControlGet, api.trafficControl)
	addRPCRoute(handlers, v2TrafficControlStatus, api.trafficControlStatus)
	addRPCRoute(handlers, v2TrafficControlPut, api.saveTrafficControl)
	addRPCRoute(handlers, v2InboundConfigPut, api.saveInboundConfig)
	addRPCRoute(handlers, v2InboundsGet, api.inbounds)
	addRPCRoute(handlers, v2InboundCapabilities, api.inboundCapabilities)
	addRPCRoute(handlers, v2InboundStatuses, api.inboundStatuses)
	addRPCRoute(handlers, v2InboundEvents, api.inboundEvents)
	addRPCRoute(handlers, v2InboundRetry, api.retryInbound)
	addRPCRoute(handlers, v2InboundsPost, api.createInbound)
	addRPCRoute(handlers, v2InboundGet, api.inbound)
	addRPCRoute(handlers, v2InboundPut, api.saveInbound)
	addRPCRoute(handlers, v2InboundDelete, api.deleteInbound)
}

type trafficControlStatusReader interface {
	TrafficControlStatus() trafficcontrol.Status
}

func (a v2API) trafficControlStatus(_ context.Context, _ *emptyRequest) (*trafficcontrol.Status, error) {
	reader, ok := a.services.Inbounds.(trafficControlStatusReader)
	if !ok {
		return nil, unavailable("traffic control diagnostics are unavailable")
	}
	status := reader.TrafficControlStatus()
	return &status, nil
}

type trafficControlStore interface {
	TrafficControl(context.Context) (trafficcontrol.Config, error)
	SaveTrafficControl(context.Context, trafficcontrol.Config) error
}

func (a v2API) trafficControl(ctx context.Context, _ *emptyRequest) (*trafficcontrol.Config, error) {
	backend, ok := a.services.Inbounds.(trafficControlStore)
	if !ok {
		return nil, unavailable("traffic control is unavailable")
	}
	cfg, err := backend.TrafficControl(ctx)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
func (a v2API) saveTrafficControl(ctx context.Context, cfg *trafficcontrol.Config) (*trafficcontrol.Config, error) {
	backend, ok := a.services.Inbounds.(trafficControlStore)
	if !ok {
		return nil, unavailable("traffic control is unavailable")
	}
	if err := backend.SaveTrafficControl(ctx, *cfg); err != nil {
		return nil, badRequest(err)
	}
	return cfg, nil
}

func (a v2API) inboundCapabilities(context.Context, *emptyRequest) (*contractinbound.Capabilities, error) {
	return new(inbound.Capabilities()), nil
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
	page := max(request.Page, 1)
	pageSize := max(request.PageSize, 0)
	total := len(items)
	return &listV2[T]{Items: paginateV2(items, page, pageSize), Page: pageV2{Page: page, PageSize: pageSize, Total: total}}
}

// Runtime reads come from the listener owner, rather than inferring health from saved configuration.
type inboundRuntimeController interface {
	Statuses(context.Context) ([]contractinbound.RuntimeStatus, error)
	Events(context.Context, string) ([]contractinbound.RuntimeEvent, error)
	Retry(context.Context, string) error
}

func (a v2API) inboundStatuses(ctx context.Context, _ *emptyRequest) (*listV2[contractinbound.RuntimeStatus], error) {
	runtime, ok := a.services.Inbounds.(inboundRuntimeController)
	if !ok {
		return nil, unavailable("inbound runtime is unavailable")
	}
	items, err := runtime.Statuses(ctx)
	if err != nil {
		return nil, err
	}
	return &listV2[contractinbound.RuntimeStatus]{Items: items}, nil
}

func (a v2API) inboundEvents(ctx context.Context, req *idRequest) (*listV2[contractinbound.RuntimeEvent], error) {
	runtime, ok := a.services.Inbounds.(inboundRuntimeController)
	if !ok {
		return nil, unavailable("inbound runtime is unavailable")
	}
	items, err := runtime.Events(ctx, req.ID)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(err)
	}
	if err != nil {
		return nil, err
	}
	return &listV2[contractinbound.RuntimeEvent]{Items: items}, nil
}

func (a v2API) retryInbound(ctx context.Context, req *idRequest) (*emptyResponse, error) {
	runtime, ok := a.services.Inbounds.(inboundRuntimeController)
	if !ok {
		return nil, unavailable("inbound runtime is unavailable")
	}
	if err := runtime.Retry(ctx, req.ID); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, notFound(err)
		}
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}
