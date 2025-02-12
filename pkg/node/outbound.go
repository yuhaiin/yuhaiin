package node

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type outbound struct {
	manager *Manager
}

func NewOutbound(mamanager *Manager) *outbound {
	return &outbound{
		manager: mamanager,
	}
}

func (o *outbound) GetDialer(ctx context.Context, p *point.Point) (netapi.Proxy, error) {
	return o.getDialer(ctx, p.GetHash(), func() (*point.Point, error) { return p, nil })
}

func (o *outbound) getDialer(ctx context.Context, hash string, point func() (*point.Point, error)) (netapi.Proxy, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is empty")
	}

	return o.manager.GetStore().LoadOrCreate(ctx, hash, func() (*ProxyEntry, error) {
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

type HashKey struct{}

func (HashKey) String() string { return "Hash" }

func (o *outbound) Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error) {
	store := netapi.GetContext(ctx)

	if tag != "" {
		store.Tag = tag
		if hash := o.tagConn(tag); hash != "" {
			p, err := o.GetDialerByID(ctx, hash)
			if err == nil {
				return p, nil
			}
		}
	}

	switch str {
	case bypass.Mode_direct.String():
		return direct.Default, nil
	case bypass.Mode_block.String():
		metrics.Counter.AddBlockConnection(str)
		return reject.Default, nil
	}

	if len(network) < 3 {
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	var point *point.Point
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
func (o *outbound) GetDialerByID(ctx context.Context, hash string) (netapi.Proxy, error) {
	return o.getDialer(ctx, hash, func() (*point.Point, error) {
		p, ok := o.manager.GetNode(hash)
		if !ok {
			return nil, fmt.Errorf("node not found")
		}
		return p, nil
	})
}

func (o *outbound) tagConn(tag string) string {
	for {
		t, ok := o.manager.ExistTag(tag)
		if !ok || len(t.GetHash()) <= 0 {
			return ""
		}

		if t.GetType() == pt.TagType_mirror {
			if tag == t.GetHash()[0] {
				return ""
			}
			tag = t.GetHash()[0]
			continue
		}

		return t.GetHash()[rand.IntN(len(t.GetHash()))]
	}
}

func (o *outbound) Do(req *http.Request) (*http.Response, error) {
	f, err := o.Get(req.Context(), "tcp", bypass.Mode_proxy.String(), "")
	if err != nil {
		return nil, err
	}

	c := &http.Client{
		Timeout: time.Minute * 2,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}

				return f.Conn(ctx, ad)
			},
		},
	}

	r, err := c.Do(req)
	if err == nil {
		return r, nil
	}

	f = direct.Default

	return c.Do(req)
}
