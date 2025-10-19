package node

import (
	"context"
	"fmt"
	"math/rand/v2"

	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type Outbound struct {
	manager *Manager
}

func (o *Outbound) GetDialer(ctx context.Context, p *node.Point) (netapi.Proxy, error) {
	return o.getDialer(ctx, p.GetHash(), func() (*node.Point, error) { return p, nil })
}

func (o *Outbound) getDialer(ctx context.Context, hash string, point func() (*node.Point, error)) (netapi.Proxy, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is empty")
	}

	return o.manager.Store().LoadOrCreate(ctx, hash, func() (*ProxyEntry, error) {
		p, err := point()
		if err != nil {
			return nil, err
		}

		r, err := register.Dialer(p)
		if err != nil {
			return nil, err
		}

		return &ProxyEntry{
			Proxy:  r,
			Config: p,
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
	case config.Mode_direct.String():
		return direct.Default, nil
	case config.Mode_block.String():
		metrics.Counter.AddBlockConnection(str)
		return reject.Default, nil
	}

	if len(network) < 3 {
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	var point *node.Point
	switch network[:3] {
	case "tcp":
		point = o.manager.GetNow(true)
	case "udp":
		point = o.manager.GetNow(false)
	default:
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	return o.GetDialer(ctx, point)
}

// GetDialerByID if id is not exists or point dial failed, it will return nil
func (o *Outbound) GetDialerByID(ctx context.Context, hash string) (netapi.Proxy, error) {
	return o.getDialer(ctx, hash, func() (*node.Point, error) {
		p, ok := o.manager.GetNode(hash)
		if !ok {
			return nil, fmt.Errorf("node not found")
		}
		return p, nil
	})
}

func (o *Outbound) tagConn(tag string) string {
	for {
		t, ok := o.manager.GetTag(tag)
		if !ok || len(t.GetHash()) <= 0 {
			return ""
		}

		if t.GetType() == node.TagType_mirror {
			if tag == t.GetHash()[0] {
				return ""
			}
			tag = t.GetHash()[0]
			continue
		}

		return t.GetHash()[rand.IntN(len(t.GetHash()))]
	}
}
