package node

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node/register"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

type outbound struct {
	manager  *manager
	UDP, TCP *point.Point

	lruCache *lru.LRU[string, netapi.Proxy]
}

func NewOutbound(tcp, udp *point.Point, mamanager *manager) *outbound {
	return &outbound{
		manager:  mamanager,
		UDP:      udp,
		TCP:      tcp,
		lruCache: lru.NewLru(lru.WithCapacity[string, netapi.Proxy](35)),
	}
}

func (o *outbound) Save(p *point.Point, udp bool) {
	if udp {
		o.UDP = p
	} else {
		o.TCP = p
	}
}

type TagKey struct{}

func (TagKey) String() string { return "Tag" }

func (o *outbound) Conn(ctx context.Context, host netapi.Address) (_ net.Conn, err error) {
	if tc := o.tagConn(ctx, host); tc != nil {
		return tc.Conn(ctx, host)
	}

	p, ok := o.lruCache.Load(o.TCP.Hash)
	if !ok {
		p, err = register.Dialer(o.TCP)
		if err != nil {
			return nil, err
		}

		o.lruCache.Add(o.TCP.Hash, p)
	}

	netapi.StoreFromContext(ctx).Add(HashKey{}, o.TCP.Hash)

	return p.Conn(ctx, host)
}

func (o *outbound) PacketConn(ctx context.Context, host netapi.Address) (_ net.PacketConn, err error) {
	if tc := o.tagConn(ctx, host); tc != nil {
		return tc.PacketConn(ctx, host)
	}

	p, ok := o.lruCache.Load(o.UDP.Hash)
	if !ok {
		p, err = register.Dialer(o.UDP)
		if err != nil {
			return nil, err
		}

		o.lruCache.Add(o.UDP.Hash, p)
	}

	netapi.StoreFromContext(ctx).Add(HashKey{}, o.UDP.Hash)
	return p.PacketConn(ctx, host)
}

type HashKey struct{}

func (HashKey) String() string { return "Hash" }

func (o *outbound) tagConn(ctx context.Context, host netapi.Address) netapi.Proxy {

	tag, ok := netapi.Get[string](ctx, TagKey{})
	if !ok {
		return nil
	}

_retry:
	t, ok := o.manager.ExistTag(tag)
	if !ok || len(t.Hash) <= 0 {
		return nil
	}

	if t.Type == pt.Type_mirror {
		if tag == t.Hash[0] {
			return nil
		}
		tag = t.Hash[0]
		goto _retry
	}

	hash := t.Hash[rand.Intn(len(t.Hash))]

	v, ok := o.lruCache.Load(hash)
	if !ok {
		p, ok := o.manager.GetNode(hash)
		if !ok {
			return nil
		}

		var err error
		v, err = register.Dialer(p)
		if err != nil {
			return nil
		}
		o.lruCache.Add(hash, v)
	}

	netapi.StoreFromContext(ctx).Add(HashKey{}, hash)
	return v
}

func (o *outbound) Do(req *http.Request) (*http.Response, error) {
	f := o.Conn

	c := &http.Client{
		Timeout: time.Minute * 2,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := netapi.ParseAddress(netapi.PaseNetwork(network), addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}

				return f(ctx, ad)
			},
		},
	}

	r, err := c.Do(req)
	if err == nil {
		return r, nil
	}

	f = direct.Default.Conn

	return c.Do(req)
}
