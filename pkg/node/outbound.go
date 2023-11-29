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
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

type outbound struct {
	manager *manager
	db      *jsondb.DB[*node.Node]

	lruCache *lru.LRU[string, netapi.Proxy]
}

func NewOutbound(db *jsondb.DB[*node.Node], mamanager *manager) *outbound {
	return &outbound{
		manager:  mamanager,
		db:       db,
		lruCache: lru.NewLru(lru.WithCapacity[string, netapi.Proxy](35)),
	}
}

type TagKey struct{}

func (TagKey) String() string { return "Tag" }

func (o *outbound) Conn(ctx context.Context, host netapi.Address) (_ net.Conn, err error) {
	if tc := o.tagConn(ctx, host); tc != nil {
		return tc.Conn(ctx, host)
	}

	tcp := o.db.Data.Tcp

	p, err := o.GetDialer(tcp)
	if err != nil {
		return nil, err
	}

	netapi.StoreFromContext(ctx).Add(HashKey{}, tcp.Hash)

	return p.Conn(ctx, host)
}

func (o *outbound) GetDialer(p *point.Point) (netapi.Proxy, error) {
	if p.Hash == "" {
		return register.Dialer(p)
	}

	var err error
	r, ok := o.lruCache.Load(p.Hash)
	if !ok {
		r, err = register.Dialer(p)
		if err != nil {
			return nil, err
		}

		o.lruCache.Add(p.Hash, r)
	}

	return r, nil
}

func (o *outbound) PacketConn(ctx context.Context, host netapi.Address) (_ net.PacketConn, err error) {
	if tc := o.tagConn(ctx, host); tc != nil {
		return tc.PacketConn(ctx, host)
	}

	udp := o.db.Data.Udp

	p, err := o.GetDialer(udp)
	if err != nil {
		return nil, err
	}

	netapi.StoreFromContext(ctx).Add(HashKey{}, udp.Hash)
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

	if t.Type == pt.TagType_mirror {
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
