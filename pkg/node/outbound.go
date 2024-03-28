package node

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/drop"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
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
		lruCache: lru.New(lru.WithCapacity[string, netapi.Proxy](200)),
	}
}

type TagKey struct{}

func (TagKey) String() string { return "Tag" }

func (o *outbound) getNowPoint(p *point.Point) *point.Point {
	pp, ok := o.manager.GetNodeByName(p.Group, p.Name)
	if ok {
		return pp
	}

	return p
}

func (o *outbound) GetDialer(p *point.Point) (netapi.Proxy, error) {
	if p.Hash == "" {
		return point.Dialer(p)
	}

	var err error
	r, ok := o.lruCache.Load(p.Hash)
	if !ok {
		r, err = point.Dialer(p)
		if err != nil {
			return nil, err
		}

		o.lruCache.Add(p.Hash, r)
	}

	return r, nil
}

type HashKey struct{}

func (HashKey) String() string { return "Hash" }

func (o *outbound) Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error) {
	if tag != "" {
		netapi.StoreFromContext(ctx).Add(TagKey{}, tag)
		if hash := o.tagConn(tag); hash != "" {
			p := o.GetDialerByHash(ctx, hash)
			if p != nil {
				return p, nil
			}
		}
	}

	switch str {
	case bypass.Mode_direct.String():
		return direct.Default, nil
	case bypass.Mode_block.String():
		return drop.Drop, nil
	}

	if len(network) < 3 {
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	var point *point.Point
	switch network[:3] {
	case "tcp":
		point = o.getNowPoint(o.db.Data.Tcp)
	case "udp":
		point = o.getNowPoint(o.db.Data.Udp)
	default:
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	p, err := o.GetDialer(point)
	if err != nil {
		return nil, err
	}

	netapi.StoreFromContext(ctx).Add(HashKey{}, point.Hash)
	return p, nil
}

func (o *outbound) GetDialerByHash(ctx context.Context, hash string) netapi.Proxy {
	v, ok := o.lruCache.Load(hash)
	if !ok {
		p, ok := o.manager.GetNode(hash)
		if !ok {
			return nil
		}

		var err error
		v, err = point.Dialer(p)
		if err != nil {
			return nil
		}

		o.lruCache.Add(hash, v)
	}

	netapi.StoreFromContext(ctx).Add(HashKey{}, hash)
	return v
}

func (o *outbound) tagConn(tag string) string {
_retry:
	t, ok := o.manager.ExistTag(tag)
	if !ok || len(t.Hash) <= 0 {
		return ""
	}

	if t.Type == pt.TagType_mirror {
		if tag == t.Hash[0] {
			return ""
		}
		tag = t.Hash[0]
		goto _retry
	}

	hash := t.Hash[rand.IntN(len(t.Hash))]

	return hash
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
				ad, err := netapi.ParseAddress(netapi.PaseNetwork(network), addr)
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
