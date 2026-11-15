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
	addRPCRoute(handlers, v2ShareFeeds, api.shareFeeds)
	addRPCRoute(handlers, v2ShareFeedCreate, api.createShareFeed)
	addRPCRoute(handlers, v2ShareFeedPut, api.updateShareFeed)
	addRPCRoute(handlers, v2ShareFeedDelete, api.deleteShareFeed)
	addRPCRoute(handlers, v2ShareFeedRotate, api.rotateShareFeed)
	addRPCRoute(handlers, v2ShareFeedPreview, api.previewShareFeed)
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

func (a v2API) shareFeeds(ctx context.Context, _ *emptyRequest) (*contractsubscription.ShareFeedList, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	return pointer(a.services.Subscriptions.ListShareFeeds(ctx))
}

func (a v2API) createShareFeed(ctx context.Context, request *contractsubscription.ShareFeed) (*contractsubscription.ShareFeed, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	feed, err := a.services.Subscriptions.CreateShareFeed(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &feed, nil
}

func (a v2API) updateShareFeed(ctx context.Context, request *contractsubscription.ShareFeed) (*contractsubscription.ShareFeed, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	feed, err := a.services.Subscriptions.UpdateShareFeed(ctx, *request)
	return shareFeedResult(feed, err)
}

func (a v2API) deleteShareFeed(ctx context.Context, request *contractsubscription.ShareFeedID) (*emptyResponse, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	if err := a.services.Subscriptions.DeleteShareFeed(ctx, request.ID); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, notFound(err)
		}
		return nil, err
	}
	return &emptyResponse{}, nil
}

func (a v2API) rotateShareFeed(ctx context.Context, request *contractsubscription.ShareFeedID) (*contractsubscription.ShareFeed, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	feed, err := a.services.Subscriptions.RotateShareFeedToken(ctx, request.ID)
	return shareFeedResult(feed, err)
}

func (a v2API) previewShareFeed(ctx context.Context, request *contractsubscription.ShareFeedPreviewRequest) (*contractsubscription.ShareFeedPreview, error) {
	if a.services.Subscriptions == nil {
		return nil, unavailable("subscription store is unavailable")
	}
	preview, err := a.services.Subscriptions.PreviewShareFeed(ctx, request.Entries)
	if err != nil {
		return nil, badRequest(err)
	}
	return &preview, nil
}

func shareFeedResult(feed contractsubscription.ShareFeed, err error) (*contractsubscription.ShareFeed, error) {
	switch {
	case errors.Is(err, plainstore.ErrNotFound):
		return nil, notFound(err)
	case err != nil:
		return nil, badRequest(err)
	}
	return &feed, nil
}
