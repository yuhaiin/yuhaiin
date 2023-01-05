package node

import (
	"context"
	"errors"
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
		lruCache: lru.NewLru[string, proxy.Proxy](22, 0),
	}
}

func (o *outbound) Save(p *point.Point, udp bool) {
	if udp {
		o.UDP = p
	} else {
		o.TCP = p
	}
}

var errEmptyTag = errors.New("empty tag")

type TagKey struct{}

func (TagKey) String() string { return "Tag" }

func (o *outbound) Conn(host proxy.Address) (_ net.Conn, err error) {
	tc, err := o.tagConn(host)
	if err == nil {
		return tc.Conn(host)
	} else if !errors.Is(err, errEmptyTag) {
		log.Warningln(err)
	}

	p, ok := o.lruCache.Load(o.TCP.Hash)
	if !ok {
		p, err = register.Dialer(o.TCP)
		if err != nil {
			return nil, err
		}

		o.lruCache.Add(o.TCP.Hash, p)
	}

	return p.Conn(host)
}

func (o *outbound) PacketConn(host proxy.Address) (_ net.PacketConn, err error) {
	tc, err := o.tagConn(host)
	if err == nil {
		return tc.PacketConn(host)
	} else if !errors.Is(err, errEmptyTag) {
		log.Warningln(err)
	}

	p, ok := o.lruCache.Load(o.UDP.Hash)
	if !ok {
		p, err = register.Dialer(o.UDP)
		if err != nil {
			return nil, err
		}

		o.lruCache.Add(o.UDP.Hash, p)
	}

	return p.PacketConn(host)
}

func (o *outbound) tagConn(host proxy.Address) (proxy.Proxy, error) {
	tag := proxy.Value(host, TagKey{}, "")
	if tag == "" {
		return nil, errEmptyTag
	}

	t, ok := o.manager.ExistTag(tag)
	if !ok {
		return nil, fmt.Errorf("tag %s is not exist", tag)
	}

	hash := t.Hash[rand.Intn(len(t.Hash))]

	v, ok := o.lruCache.Load(hash)
	if ok {
		return v, nil
	}

	p, ok := o.manager.GetNode(hash)
	if !ok {
		return nil, fmt.Errorf("get node from %v failed", t.Hash)
	}

	v, err := register.Dialer(p)
	if err != nil {
		return nil, err
	}

	o.lruCache.Add(hash, v)
	return v, nil
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
