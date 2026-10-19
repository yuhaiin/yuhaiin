package httpapi

import (
	"context"
	"errors"
	"fmt"
	"slices"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

// Resource operations share the same transaction/snapshot boundary as the full
// visual-editor save. Entity revisions protect edits made through either API.
type gatewayResourceRequest struct {
	Kind     string               `json:"kind"`
	ID       string               `json:"id"`
	Revision uint64               `json:"revision"`
	Gateway  *contract.Gateway    `json:"gateway,omitzero"`
	Rule     *contract.Rule       `json:"rule,omitzero"`
	Upstream *contract.Upstream   `json:"upstream,omitzero"`
	Filter   *contract.FilterList `json:"filter,omitzero"`
}

func addGatewayResourceRoutes(h *v2Handlers, services V2Services) {
	addRPCRoute(h, v2GatewayResourcesList, func(_ context.Context, _ *emptyRequest) (*contract.Config, error) {
		if services.Gateway == nil {
			return nil, unavailable("gateway is unavailable")
		}
		return new(services.Gateway.Config()), nil
	})
	addRPCRoute(h, v2GatewayResourceGet, func(_ context.Context, r *gatewayResourceRequest) (*gatewayResourceRequest, error) {
		if services.Gateway == nil {
			return nil, unavailable("gateway is unavailable")
		}
		c := services.Gateway.Config()
		switch r.Kind {
		case "gateway":
			for _, v := range c.Gateways {
				if v.ID == r.ID {
					r.Gateway = new(v)
					return r, nil
				}
			}
		case "rule":
			for _, v := range c.Rules {
				if v.ID == r.ID {
					r.Rule = new(v)
					return r, nil
				}
			}
		case "upstream":
			for _, v := range c.Upstreams {
				if v.ID == r.ID {
					r.Upstream = new(v)
					return r, nil
				}
			}
		case "filter":
			for _, v := range c.FilterLists {
				if v.ID == r.ID {
					r.Filter = new(v)
					return r, nil
				}
			}
		default:
			return nil, badRequest(fmt.Errorf("invalid gateway resource kind"))
		}
		return nil, notFound(store.ErrNotFound)
	})
	for _, operation := range []struct {
		endpoint v2Endpoint
		remove   bool
	}{{v2GatewayResourcePut, false}, {v2GatewayResourceDelete, true}} {
		addRPCRoute(h, operation.endpoint, func(ctx context.Context, r *gatewayResourceRequest) (*contract.Config, error) {
			if services.Gateway == nil {
				return nil, unavailable("gateway is unavailable")
			}
			c := services.Gateway.Config()
			var err error
			switch r.Kind {
			case "gateway":
				c.Gateways, err = editGatewayResource(c.Gateways, r.Gateway, r.ID, r.Revision, operation.remove, func(v contract.Gateway) (string, uint64) { return v.ID, v.Revision })
			case "rule":
				c.Rules, err = editGatewayResource(c.Rules, r.Rule, r.ID, r.Revision, operation.remove, func(v contract.Rule) (string, uint64) { return v.ID, v.Revision })
			case "upstream":
				c.Upstreams, err = editGatewayResource(c.Upstreams, r.Upstream, r.ID, r.Revision, operation.remove, func(v contract.Upstream) (string, uint64) { return v.ID, v.Revision })
			case "filter":
				c.FilterLists, err = editGatewayResource(c.FilterLists, r.Filter, r.ID, r.Revision, operation.remove, func(v contract.FilterList) (string, uint64) { return v.ID, v.Revision })
			default:
				err = fmt.Errorf("invalid gateway resource kind")
			}
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return nil, notFound(err)
				}
				return nil, badRequest(err)
			}
			saved, err := services.Gateway.Save(ctx, c)
			if err != nil {
				return nil, badRequest(err)
			}
			return &saved, nil
		})
	}
}

func editGatewayResource[T any](items []T, value *T, id string, revision uint64, remove bool, identity func(T) (string, uint64)) ([]T, error) {
	if !remove {
		if value == nil {
			return nil, fmt.Errorf("resource body is required")
		}
		bodyID, bodyRevision := identity(*value)
		if id != "" && id != bodyID {
			return nil, fmt.Errorf("resource ID differs from request ID")
		}
		id, revision = bodyID, bodyRevision
	}
	if id == "" {
		return nil, fmt.Errorf("resource ID is required")
	}
	index := slices.IndexFunc(items, func(v T) bool { current, _ := identity(v); return current == id })
	if index < 0 {
		if remove {
			return nil, store.ErrNotFound
		}
		if revision != 0 {
			return nil, store.ErrConflict
		}
		return append(items, *value), nil
	}
	_, currentRevision := identity(items[index])
	if revision != currentRevision {
		return nil, store.ErrConflict
	}
	if remove {
		return slices.Delete(items, index, index+1), nil
	}
	items[index] = *value
	return items, nil
}
