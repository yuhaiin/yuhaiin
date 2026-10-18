package httpapi

import (
	"context"
	"errors"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func addSubscriptionRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2SubscriptionsGet, api.subscriptions)
	addRPCRoute(handlers, v2SubscriptionsPut, api.saveSubscriptions)
	addRPCRoute(handlers, v2SubscriptionsDelete, api.deleteSubscriptions)
	addRPCRoute(handlers, v2SubscriptionsUpdate, api.updateSubscriptions)
	addRPCRoute(handlers, v2Publishes, api.publishes)
	addRPCRoute(handlers, v2PublishPut, api.savePublish)
	addRPCRoute(handlers, v2PublishDelete, api.deletePublish)
	addRPCRoute(handlers, v2PublishResolve, api.resolvePublish)
}

func (a v2API) subscriptions(ctx context.Context, _ *emptyRequest) (*contractsubscription.LinkList, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	return pointer(a.services.Subscriptions.ListLinks(ctx))
}

func (a v2API) saveSubscriptions(ctx context.Context, request *contractsubscription.LinkList) (*emptyResponse, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	if err := a.services.Subscriptions.SaveLinks(ctx, request.Items, 0); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}

func (a v2API) deleteSubscriptions(ctx context.Context, request *contractsubscription.LinkNames) (*emptyResponse, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	if err := a.services.Subscriptions.DeleteLinks(ctx, request.Names); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}

func (a v2API) updateSubscriptions(ctx context.Context, request *contractsubscription.LinkNames) (*emptyResponse, error) {
	if a.services.Subscribe == nil {
		return nil, unavailable("subscription controller is unavailable")
	}
	if err := a.services.Subscribe.Update(ctx, request.Names); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}

func (a v2API) publishes(ctx context.Context, _ *emptyRequest) (*contractsubscription.PublishList, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	return pointer(a.services.Subscriptions.ListPublishes(ctx))
}

func (a v2API) savePublish(ctx context.Context, request *contractsubscription.Publish) (*emptyResponse, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	if err := a.services.Subscriptions.SavePublish(ctx, *request, 0); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}

type publishNameRequest struct {
	Name string `json:"name"`
}

func (a v2API) deletePublish(ctx context.Context, request *publishNameRequest) (*emptyResponse, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	if err := a.services.Subscriptions.DeletePublish(ctx, request.Name); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, &rpcError{status: 404, code: "not_found", message: err.Error()}
		}
		return nil, err
	}
	return &emptyResponse{}, nil
}

func (a v2API) resolvePublish(ctx context.Context, request *contractsubscription.ResolvePublishRequest) (*contractsubscription.ResolvePublishResponse, error) {
	if a.services.Subscribe == nil {
		return nil, unavailable("subscription controller is unavailable")
	}
	value, err := a.services.Subscribe.ResolvePublish(ctx, request.Name, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}
