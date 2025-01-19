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
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

type outbound struct {
	manager *manager
	db      *jsondb.DB[*node.Node]

	lruCache *lru.SyncLru[string, netapi.Proxy]
}

func NewOutbound(db *jsondb.DB[*node.Node], mamanager *manager) *outbound {
	return &outbound{
		manager:  mamanager,
		db:       db,
		lruCache: lru.NewSyncLru(lru.WithCapacity[string, netapi.Proxy](200)),
	}
}

func (o *outbound) getNowPoint(p *point.Point) *point.Point {
	pp, ok := o.manager.GetNodeByName(p.GetGroup(), p.GetName())
	if ok {
		return pp
	}

	return p
}

func (o *outbound) GetDialer(p *point.Point) (netapi.Proxy, error) {
	if p.GetHash() == "" {
		return register.Dialer(p)
	}

	var err error
	r, ok := o.lruCache.Load(p.GetHash())
	if !ok {
		r, err = register.Dialer(p)
		if err != nil {
			return nil, err
		}

		o.lruCache.Add(p.GetHash(), r)
	}

	return r, nil
}

type HashKey struct{}

func (HashKey) String() string { return "Hash" }

func (o *outbound) Get(ctx context.Context, network string, str string, tag string) (netapi.Proxy, error) {
	store := netapi.GetContext(ctx)

	if tag != "" {
		store.Tag = tag
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
		metrics.Counter.AddBlockConnection(str)
		return reject.Default, nil
	}

	if len(network) < 3 {
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	var point *point.Point
	switch network[:3] {
	case "tcp":
		point = o.getNowPoint(o.db.Data.GetTcp())
	case "udp":
		point = o.getNowPoint(o.db.Data.GetUdp())
	default:
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	p, err := o.GetDialer(point)
	if err != nil {
		return nil, err
	}

	store.Hash = point.GetHash()
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
		v, err = register.Dialer(p)
		if err != nil {
			return nil
		}

		o.lruCache.Add(hash, v)
	}

	netapi.GetContext(ctx).Hash = hash
	return v
}

func (o *outbound) tagConn(tag string) string {
_retry:
	t, ok := o.manager.ExistTag(tag)
	if !ok || len(t.GetHash()) <= 0 {
		return ""
	}

	if t.GetType() == pt.TagType_mirror {
		if tag == t.GetHash()[0] {
			return ""
		}
		tag = t.GetHash()[0]
		goto _retry
	}

	hash := t.GetHash()[rand.IntN(len(t.GetHash()))]

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
