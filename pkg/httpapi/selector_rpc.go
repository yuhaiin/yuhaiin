package httpapi

import (
	"context"
	"errors"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func addSelectorRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	a := v2API{services: services}
	addRPCRoute(handlers, v2SelectorsGet, a.selectors)
	addRPCRoute(handlers, v2SelectorPut, a.saveSelector)
	addRPCRoute(handlers, v2SelectorDelete, a.deleteSelector)
	addRPCRoute(handlers, v2SelectorReferences, a.selectorReferences)
	addRPCRoute(handlers, v2SelectorStatus, a.selectorStatus)
	addRPCRoute(handlers, v2MonitoringGet, a.monitoringGet)
	addRPCRoute(handlers, v2MonitoringPut, a.monitoringPut)
	addRPCRoute(handlers, v2MonitoringNetwork, a.monitoringNetwork)
}

func (a v2API) selectors(ctx context.Context, _ *emptyRequest) (*contractnode.SelectorList, error) {
	if a.services.Selectors == nil {
		return nil, unavailable("outbound selectors are unavailable")
	}
	items, err := a.services.Selectors.List(ctx)
	return &contractnode.SelectorList{Items: items}, err
}

func (a v2API) saveSelector(ctx context.Context, request *contractnode.Selector) (*contractnode.Selector, error) {
	if a.services.Selectors == nil {
		return nil, unavailable("outbound selectors are unavailable")
	}
	item, err := a.services.Selectors.Save(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &item, nil
}

func (a v2API) deleteSelector(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	if a.services.Selectors == nil {
		return nil, unavailable("outbound selectors are unavailable")
	}
	if err := a.services.Selectors.Delete(ctx, request.ID); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, notFound(err)
		}
		return nil, err
	}
	return &emptyResponse{}, nil
}

func (a v2API) selectorReferences(ctx context.Context, request *idRequest) (*struct {
	Items []contractroute.Reference `json:"items"`
}, error) {
	if a.services.Selectors == nil {
		return nil, unavailable("outbound selectors are unavailable")
	}
	refs, err := a.services.Selectors.References(ctx, request.ID)
	return &struct {
		Items []contractroute.Reference `json:"items"`
	}{Items: refs}, err
}

func (a v2API) selectorStatus(ctx context.Context, request *idRequest) (*contractnode.SelectorRuntimeStatus, error) {
	provider, ok := a.services.Selectors.(interface {
		Status(context.Context, string) (contractnode.SelectorRuntimeStatus, error)
	})
	if !ok {
		return nil, unavailable("selector runtime is unavailable")
	}
	status, err := provider.Status(ctx, request.ID)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(err)
	}
	return &status, err
}

type monitoringProvider interface {
	Monitoring(context.Context) (contractnode.MonitoringStatus, error)
	SaveMonitoring(context.Context, contractnode.MonitoringConfig) (contractnode.MonitoringStatus, error)
	SetMonitoringNetworkState(context.Context, contractnode.MonitoringNetworkState) (contractnode.MonitoringStatus, error)
}

func (a v2API) monitoringGet(ctx context.Context, _ *emptyRequest) (*contractnode.MonitoringStatus, error) {
	p, ok := a.services.Node.(monitoringProvider)
	if !ok {
		return nil, unavailable("node monitoring is unavailable")
	}
	result, err := p.Monitoring(ctx)
	return &result, err
}
func (a v2API) monitoringPut(ctx context.Context, c *contractnode.MonitoringConfig) (*contractnode.MonitoringStatus, error) {
	p, ok := a.services.Node.(monitoringProvider)
	if !ok {
		return nil, unavailable("node monitoring is unavailable")
	}
	result, err := p.SaveMonitoring(ctx, *c)
	if err != nil {
		return nil, badRequest(err)
	}
	return &result, nil
}
func (a v2API) monitoringNetwork(ctx context.Context, n *contractnode.MonitoringNetworkState) (*contractnode.MonitoringStatus, error) {
	p, ok := a.services.Node.(monitoringProvider)
	if !ok {
		return nil, unavailable("node monitoring is unavailable")
	}
	result, err := p.SetMonitoringNetworkState(ctx, *n)
	if err != nil {
		return nil, badRequest(err)
	}
	return &result, nil
}
