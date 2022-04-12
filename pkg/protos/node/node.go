package node

import (
	"fmt"
	"reflect"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func (p *Point) Conn() (r proxy.Proxy, err error) {
	r = direct.DefaultDirect
	for _, v := range p.Protocols {
		r, err = conn(v.Protocol, r)
		if err != nil {
			return
		}
	}

	return
}

var execProtocol syncmap.SyncMap[reflect.Type, func(any, proxy.Proxy) (proxy.Proxy, error)]

func RegisterProtocol[T isPointProtocol_Protocol](f func(T, proxy.Proxy) (proxy.Proxy, error)) {
	if f == nil {
		return
	}

	var z T
	execProtocol.Store(reflect.TypeOf(z), func(a any, p proxy.Proxy) (proxy.Proxy, error) { return f(a.(T), p) })
}

func conn(p isPointProtocol_Protocol, z proxy.Proxy) (proxy.Proxy, error) {
	if p == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	conn, ok := execProtocol.Load(reflect.TypeOf(p))
	if !ok {
		return nil, fmt.Errorf("protocol %v is not support", p)
	}

	return conn(p, z)
}
