package node

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node/register"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

type outbound struct {
	manager  *manager
	UDP, TCP *point.Point

	lruCache *lru.LRU[string, proxy.Proxy]
}

func NewOutbound(tcp, udp *point.Point, mamanager *manager) *outbound {
	return &outbound{
		manager:  mamanager,
		UDP:      udp,
		TCP:      tcp,
		lruCache: lru.NewLru[string, proxy.Proxy](35, 0),
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

func (o *outbound) Conn(host proxy.Address) (_ net.Conn, err error) {
	if tc := o.tagConn(host); tc != nil {
		return tc.Conn(host)
	}

	p, ok := o.lruCache.Load(o.TCP.Hash)
	if !ok {
		p, err = register.Dialer(o.TCP)
		if err != nil {
			return nil, err
		}

		o.lruCache.Add(o.TCP.Hash, p)
	}

	host.WithValue(HashKey{}, o.TCP.Hash)
	return p.Conn(host)
}

func (o *outbound) PacketConn(host proxy.Address) (_ net.PacketConn, err error) {
	if tc := o.tagConn(host); tc != nil {
		return tc.PacketConn(host)
	}

	p, ok := o.lruCache.Load(o.UDP.Hash)
	if !ok {
		p, err = register.Dialer(o.UDP)
		if err != nil {
			return nil, err
		}

		o.lruCache.Add(o.UDP.Hash, p)
	}

	host.WithValue(HashKey{}, o.UDP.Hash)
	return p.PacketConn(host)
}

type HashKey struct{}

func (HashKey) String() string { return "Hash" }

func (o *outbound) tagConn(host proxy.Address) proxy.Proxy {
	tag := proxy.Value(host, TagKey{}, "")
	if tag == "" {
		return nil
	}

	t, ok := o.manager.ExistTag(tag)
	if !ok {
		return nil
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

	host.WithValue(HashKey{}, hash)
	return v
}

func (o *outbound) Do(req *http.Request) (*http.Response, error) {
	f := o.Conn

	c := &http.Client{
		Timeout: time.Minute * 2,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Debugln("dial:", network, addr)
				ad, err := proxy.ParseAddress(proxy.PaseNetwork(network), addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %w", err)
				}

				return f(ad)
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
