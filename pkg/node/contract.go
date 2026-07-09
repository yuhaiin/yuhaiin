package node

import (
	"context"
	"errors"
	"net"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type ContractController struct {
	manager *Manager
}

func NewContractController(manager *Manager) ContractController {
	return ContractController{
		manager: manager,
	}
}

func (c ContractController) Selected(ctx context.Context) (contractnode.Selection, error) {
	if c.manager == nil {
		return contractnode.Selection{}, errors.New("node manager is unavailable")
	}
	return c.manager.SelectedContract(ctx), nil
}

func (c ContractController) Active(ctx context.Context) ([]contractnode.Node, error) {
	if c.manager == nil {
		return nil, errors.New("node manager is unavailable")
	}
	return c.manager.ActiveContract(ctx), nil
}

func (c ContractController) Save(ctx context.Context, node contractnode.Node) (contractnode.Node, error) {
	if c.manager == nil {
		return contractnode.Node{}, errors.New("node manager is unavailable")
	}
	return c.manager.SaveContract(ctx, node)
}

func (c ContractController) Remove(ctx context.Context, id string) error {
	if c.manager == nil {
		return errors.New("node manager is unavailable")
	}
	return c.manager.DeleteNode(id)
}

func (c ContractController) Use(ctx context.Context, id string) error {
	if c.manager == nil {
		return errors.New("node manager is unavailable")
	}
	return c.manager.UsePoint(id)
}

func (c ContractController) Close(ctx context.Context, id string) error {
	if c.manager == nil {
		return errors.New("node manager is unavailable")
	}
	if id == "" {
		return nil
	}
	c.manager.store.Delete(id)
	return nil
}

type latencyDialer struct {
	netapi.Proxy
	ipv6 bool
}

func (w *latencyDialer) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	netctx := netapi.GetContext(ctx)
	if w.ipv6 {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv6)
	} else {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
	}
	return w.Proxy.Conn(netctx, a)
}

func (w *latencyDialer) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	netctx := netapi.GetContext(ctx)
	if w.ipv6 {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv6)
	} else {
		netctx.ConnOptions().Resolver().SetMode(netapi.ResolverModePreferIPv4)
	}
	return w.Proxy.PacketConn(netctx, a)
}

func (c ContractController) Latency(ctx context.Context, id string, req contractnode.LatencyRequest) (contractnode.LatencyResponse, error) {
	if c.manager == nil {
		return contractnode.LatencyResponse{}, errors.New("node manager is unavailable")
	}
	px, err := c.manager.Outbound().GetDialerByID(ctx, id)
	if err != nil {
		return contractnode.LatencyResponse{}, err
	}
	px = &latencyDialer{Proxy: px, ipv6: req.IPv6}
	return latency.Latency(req, px)
}

type ContractSubscriptionController struct {
	subscribe *Subscribe
}

func NewContractSubscriptionController(manager *Manager, nodes *plainstore.NodeStore, subscriptions *plainstore.SubscriptionStore) ContractSubscriptionController {
	return ContractSubscriptionController{subscribe: NewSubscribe(manager, nodes, subscriptions)}
}

func (c ContractSubscriptionController) Update(ctx context.Context, names []string) error {
	if c.subscribe == nil {
		return errors.New("subscription controller is unavailable")
	}
	return c.subscribe.update(ctx, names...)
}

func (c ContractSubscriptionController) ResolvePublish(ctx context.Context, name string, req contractsubscription.ResolvePublishRequest) (contractsubscription.ResolvePublishResponse, error) {
	if c.subscribe == nil {
		return contractsubscription.ResolvePublishResponse{}, errors.New("subscription controller is unavailable")
	}
	return c.subscribe.ResolvePublishContract(ctx, name, req)
}
