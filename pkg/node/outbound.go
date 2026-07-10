package node

import (
	"context"
	"fmt"
	"math/rand/v2"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type Outbound struct {
	manager *Manager
}

func (o *Outbound) getContractDialer(ctx context.Context, hash string, load func() (contractnode.Node, error)) (netapi.Proxy, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is empty")
	}

	return o.manager.Store().LoadOrCreate(ctx, hash, func() (*ProxyEntry, error) {
		node, err := load()
		if err != nil {
			return nil, err
		}
		r, err := register.ContractDialer(node)
		if err != nil {
			return nil, err
		}
		return &ProxyEntry{
			Proxy:          r,
			ContractConfig: &node,
			Name:           node.Name,
		}, nil
	})
}

func (o *Outbound) Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error) {
	store := netapi.GetContext(ctx)

	if tag != "" {
		store.SetTag(tag)
		if hash := o.tagConn(tag); hash != "" {
			p, err := o.GetDialerByID(ctx, hash)
			if err == nil {
				return p, nil
			}
		}
	}

	switch str {
	case "direct":
		return direct.Default, nil
	case "block":
		metrics.Counter.AddBlockConnection(str)
		return reject.Default, nil
	}

	if len(network) < 3 {
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	switch network[:3] {
	case "tcp":
		if contractNode, ok, err := o.manager.persist.GetContractNow(true); err == nil && ok {
			return o.getContractDialer(ctx, contractNode.ID, func() (contractnode.Node, error) { return contractNode, nil })
		}
		return nil, fmt.Errorf("selected tcp node not found")
	case "udp":
		if contractNode, ok, err := o.manager.persist.GetContractNow(false); err == nil && ok {
			return o.getContractDialer(ctx, contractNode.ID, func() (contractnode.Node, error) { return contractNode, nil })
		}
		return nil, fmt.Errorf("selected udp node not found")
	default:
		return nil, fmt.Errorf("invalid network: %s", network)
	}
}

// GetDialerByID if id is not exists or point dial failed, it will return nil
func (o *Outbound) GetDialerByID(ctx context.Context, hash string) (netapi.Proxy, error) {
	if contractNode, ok, err := o.manager.persist.GetContractNode(hash); err != nil {
		return nil, err
	} else if ok {
		return o.getContractDialer(ctx, hash, func() (contractnode.Node, error) { return contractNode, nil })
	}

	return nil, fmt.Errorf("node not found")
}

func (o *Outbound) tagConn(tag string) string {
	for {
		kind, targets, ok := o.manager.GetContractTag(tag)
		if !ok || len(targets) <= 0 {
			return ""
		}

		if kind == "mirror" {
			if tag == targets[0] {
				return ""
			}
			tag = targets[0]
			continue
		}

		return targets[rand.IntN(len(targets))]
	}
}
