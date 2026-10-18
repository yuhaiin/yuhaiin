package httpapi

import (
	"context"
	"errors"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type hostRequest struct {
	Host string `json:"host"`
}

func (a v2API) hostEntriesController() (contractresolver.HostEntries, error) {
	if controller, ok := a.services.ResolverConfig.(contractresolver.HostEntries); ok {
		return controller, nil
	}
	return nil, unavailable("host entry controller is unavailable")
}

func (a v2API) hostEntries(ctx context.Context, request *listRequest) (*listV2[contractresolver.HostEntry], error) {
	controller, err := a.hostEntriesController()
	if err != nil {
		return nil, err
	}
	page := max(1, request.Page)
	size := request.PageSize
	if size <= 0 {
		size = 25
	}
	size = min(100, size)
	items, total, err := controller.ListHostEntries(ctx, page, size, request.Query)
	if err != nil {
		return nil, err
	}
	return &listV2[contractresolver.HostEntry]{Items: items, Page: pageV2{Page: page, PageSize: size, Total: total}}, nil
}

func (a v2API) hostEntry(ctx context.Context, request *hostRequest) (*contractresolver.HostEntry, error) {
	controller, err := a.hostEntriesController()
	if err != nil {
		return nil, err
	}
	item, err := controller.HostEntry(ctx, request.Host)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(err)
	}
	return new(item), err
}

func (a v2API) createHostEntry(ctx context.Context, request *contractresolver.HostEntry) (*contractresolver.HostEntry, error) {
	return a.writeHostEntry(ctx, request, true)
}

func (a v2API) saveHostEntry(ctx context.Context, request *contractresolver.HostEntry) (*contractresolver.HostEntry, error) {
	return a.writeHostEntry(ctx, request, false)
}

func (a v2API) writeHostEntry(ctx context.Context, request *contractresolver.HostEntry, create bool) (*contractresolver.HostEntry, error) {
	if err := request.Validate(); err != nil {
		return nil, badRequest(err)
	}
	controller, err := a.hostEntriesController()
	if err != nil {
		return nil, err
	}
	item, err := controller.SaveHostEntry(ctx, *request, create)
	if errors.Is(err, contractresolver.ErrInvalidHostEntry) {
		return nil, badRequest(err)
	}
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(err)
	}
	return new(item), err
}

func (a v2API) deleteHostEntry(ctx context.Context, request *hostRequest) (*emptyResponse, error) {
	controller, err := a.hostEntriesController()
	if err != nil {
		return nil, err
	}
	err = controller.DeleteHostEntry(ctx, request.Host)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(err)
	}
	return &emptyResponse{}, err
}
