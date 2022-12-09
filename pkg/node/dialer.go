package node

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node/register"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
)

type outboundPoint struct {
	*point.Point
	proxy.Proxy
}

type outbound struct {
	manager  *manager
	udp, tcp outboundPoint

	lock sync.RWMutex
}

func NewOutbound(tcp, udp *point.Point, mamanager *manager) *outbound {
	return &outbound{
		manager: mamanager,
		udp:     outboundPoint{udp, nil},
		tcp:     outboundPoint{tcp, nil},
	}
}

func (o *outbound) Save(p *point.Point, udp bool) {
	o.lock.Lock()
	defer o.lock.Unlock()
	if udp && o.udp.Hash != p.Hash {
		o.udp = outboundPoint{p, nil}
	} else if o.tcp.Hash != p.Hash {
		o.tcp = outboundPoint{p, nil}
	}
}

func (o *outbound) refresh() {
	o.udp.Proxy = nil
	o.tcp.Proxy = nil
}

func (o *outbound) Point(udp bool) *point.Point {
	var now *point.Point

	if udp {
		now = o.udp.Point
	} else {
		now = o.tcp.Point
	}

	if now == nil {
		return &point.Point{}
	}

	p, ok := o.manager.GetNodeByName(now.Group, now.Name)
	if !ok {
		return now
	}

	return p
}

type TagKey struct{}

func (TagKey) String() string { return "Tag" }

func (o *outbound) Conn(host proxy.Address) (_ net.Conn, err error) {
	if tag := proxy.Value(host, TagKey{}, ""); tag != "" {
		tc, err := o.tagConn(tag)
		if err == nil {
			return tc.Conn(host)
		} else {
			log.Warningln("get dialer by tag failed:", err)
		}
	}

	if o.tcp.Proxy == nil {
		o.tcp.Proxy, err = register.Dialer(o.Point(false))
		if err != nil {
			return nil, err
		}
	}

	return o.tcp.Conn(host)
}

func (o *outbound) PacketConn(host proxy.Address) (_ net.PacketConn, err error) {
	if tag := proxy.Value(host, TagKey{}, ""); tag != "" {
		tc, err := o.tagConn(tag)
		if err == nil {
			return tc.PacketConn(host)
		} else {
			log.Warningln("get dialer by tag failed:", err)
		}
	}

	if o.udp.Proxy == nil {
		o.udp.Proxy, err = register.Dialer(o.Point(true))
		if err != nil {
			return nil, err
		}
	}

	return o.udp.PacketConn(host)
}

func (o *outbound) tagConn(tag string) (proxy.Proxy, error) {
	t, ok := o.manager.ExistTag(tag)
	if !ok {
		return nil, fmt.Errorf("tag %s is not exist", tag)
	}

	p, ok := o.manager.GetNode(t.Hash[rand.Intn(len(t.Hash))])
	if !ok {
		return nil, fmt.Errorf("get node from %v failed", t.Hash)
	}

	return register.Dialer(p)
}

func (o *outbound) Do(req *http.Request) (*http.Response, error) {
	f := direct.Default.Conn

	c := &http.Client{
		Timeout: time.Minute * 2,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Debugln("dial:", network, addr)
				ad, err := proxy.ParseAddress(network, addr)
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

	f = o.Conn

	return c.Do(req)
}
